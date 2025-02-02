use crate::metrics;
use anyhow::Result;
use bytes::BytesMut;
use io_uring::{IoUring, opcode, types};
use libc::iovec;
use lightway_core::IOCallbackResult;
use parking_lot::Mutex;
use std::{
    cell::UnsafeCell,
    os::unix::io::{AsRawFd, RawFd},
    sync::{
        Arc,
        atomic::{AtomicU32, AtomicUsize, Ordering},
    },
    thread,
    time::Duration,
};

const DEFAULT_BUFFER_SIZE: usize = 2048;

#[cfg(not(feature = "iouring-bufsize"))]
const BUFFER_SIZE: usize = DEFAULT_BUFFER_SIZE;

#[cfg(feature = "iouring-bufsize")]
const MAX_BUFFER_SIZE: usize = 65536;
#[cfg(feature = "iouring-bufsize")]
const BUFFER_SIZE: usize = {
    let size = std::env!("IOURING_BUFFER_SIZE")
        .parse::<usize>()
        .expect("IOURING_BUFFER_SIZE must be a valid usize");
    assert!(size <= MAX_BUFFER_SIZE, "Buffer size cannot exceed 64KB");
    size
};

#[repr(align(128))]
struct Buffer {
    data: UnsafeCell<[u8; BUFFER_SIZE]>,
    state: AtomicU32, // 0 = free, 1 = in_flight, 2 = completed
    length: AtomicU32,
}

#[allow(unsafe_code)]
unsafe impl Send for Buffer {}
#[allow(unsafe_code)]
unsafe impl Sync for Buffer {}

impl Buffer {
    fn new() -> Self {
        Self {
            data: UnsafeCell::new([0u8; BUFFER_SIZE]),
            state: AtomicU32::new(0),
            length: AtomicU32::new(0),
        }
    }
}

struct BufferPool {
    buffers: Vec<Buffer>,
    read_idx: AtomicUsize,
}

/// IO-uring Struct
pub struct IOUring<T: AsRawFd> {
    owned_fd: Arc<T>,
    rx_pool: Arc<BufferPool>,
    tx_pool: Arc<BufferPool>,
    ring: Arc<IoUring>,
    submission_lock: Arc<Mutex<()>>,
    write_index: AtomicUsize,
}

#[allow(unsafe_code)]
impl<T: AsRawFd> IOUring<T> {
    /// Create `IOUring` struct
    pub async fn new(
        owned_fd: Arc<T>,
        ring_size: usize,
        _channel_size: usize,
        mtu: usize,
        sqpoll_idle_time: Duration,
    ) -> Result<Self> {
        assert!(mtu <= BUFFER_SIZE);

        let rx_pool = Arc::new(BufferPool {
            buffers: (0..ring_size / 2).map(|_| Buffer::new()).collect(),
            read_idx: AtomicUsize::new(0),
        });

        let tx_pool = Arc::new(BufferPool {
            buffers: (0..ring_size / 2).map(|_| Buffer::new()).collect(),
            read_idx: AtomicUsize::new(0),
        });

        let ring = Arc::new(
            IoUring::builder()
                .setup_sqpoll(sqpoll_idle_time.as_millis() as u32)
                .build(ring_size as u32)?,
        );

        let submission_lock = Arc::new(Mutex::new(()));

        let rx_pool_clone = rx_pool.clone();
        let tx_pool_clone = tx_pool.clone();
        let ring_clone = ring.clone();
        let lock_clone = submission_lock.clone();
        let fd = owned_fd.as_raw_fd();

        thread::Builder::new()
            .name("io_uring-main".to_string())
            .spawn(move || {
                tokio::runtime::Builder::new_current_thread()
                    .enable_io()
                    .build()
                    .expect("Failed building Tokio Runtime")
                    .block_on(iouring_task(
                        fd,
                        rx_pool_clone,
                        tx_pool_clone,
                        ring_clone,
                        lock_clone,
                    ))
            })?;

        Ok(Self {
            owned_fd,
            rx_pool,
            tx_pool,
            ring,
            submission_lock,
            write_index: AtomicUsize::new(0),
        })
    }

    /// Retrieve a reference to the underlying device
    pub fn owned_fd(&self) -> &T {
        &self.owned_fd
    }

    /// Send packet on Tun device (push to RING and submit)
    pub fn try_send(&self, buf: BytesMut) -> IOCallbackResult<usize> {
        let len = buf.len();
        if len > BUFFER_SIZE {
            return IOCallbackResult::WouldBlock;
        }

        let write_idx =
            self.write_index.fetch_add(1, Ordering::AcqRel) % self.tx_pool.buffers.len();
        let buffer = &self.tx_pool.buffers[write_idx];

        // Check if buffer is free (state = 0)
        if buffer
            .state
            .compare_exchange(
                0,
                1, // free -> in_flight
                Ordering::AcqRel,
                Ordering::Relaxed,
            )
            .is_err()
        {
            // Out of buffers, need kernel to work faster
            // consider a bigger queue if we see this counter
            metrics::tun_iouring_tx_err();
            return IOCallbackResult::WouldBlock;
        }

        unsafe { (*buffer.data.get())[..len].copy_from_slice(&buf) };
        buffer.length.store(len as u32, Ordering::Release);

        let write_op = opcode::WriteFixed::new(
            types::Fd(self.owned_fd.as_raw_fd()),
            buffer.data.get() as *mut u8,
            len as _,
            write_idx as _,
        )
        .build()
        // NOTE: we set the index starting from after the RX_POOL part
        .user_data((self.rx_pool.buffers.len() + write_idx) as u64);

        let _guard = self.submission_lock.lock();
        unsafe {
            match self.ring.submission_shared().push(&write_op) {
                Ok(_) => IOCallbackResult::Ok(len),
                Err(_) => IOCallbackResult::WouldBlock,
            }
        }
    }

    /// Receive packet from Tun device
    pub async fn recv(&self) -> IOCallbackResult<BytesMut> {
        let idx = self.rx_pool.read_idx.load(Ordering::Relaxed) % self.rx_pool.buffers.len();
        let buffer = &self.rx_pool.buffers[idx];

        if buffer
            .state
            .compare_exchange(2, 0, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
        {
            let len = buffer.length.load(Ordering::Acquire) as usize;
            let mut new_buf = BytesMut::with_capacity(len);
            unsafe { new_buf.extend_from_slice(&(*buffer.data.get())[..len]) };
            self.rx_pool.read_idx.fetch_add(1, Ordering::Release);
            return IOCallbackResult::Ok(new_buf);
        }
        IOCallbackResult::WouldBlock
    }
}

#[allow(unsafe_code)]
async fn iouring_task(
    fd: RawFd,
    rx_pool: Arc<BufferPool>,
    tx_pool: Arc<BufferPool>,
    ring: Arc<IoUring>,
    submission_lock: Arc<Mutex<()>>,
) -> Result<()> {
    let rx_len = rx_pool.buffers.len();
    let mut iovecs = Vec::with_capacity(rx_len + tx_pool.buffers.len());

    iovecs.extend(rx_pool.buffers.iter().map(|buf| iovec {
        iov_base: buf.data.get() as *mut libc::c_void,
        iov_len: BUFFER_SIZE,
    }));

    iovecs.extend(tx_pool.buffers.iter().map(|buf| iovec {
        iov_base: buf.data.get() as *mut libc::c_void,
        iov_len: BUFFER_SIZE,
    }));

    unsafe { ring.submitter().register_buffers(&iovecs)? };

    // Initial submission of read operations
    {
        let _guard = submission_lock.lock();
        let mut sq = unsafe { ring.submission_shared() };
        for idx in 0..rx_len {
            let read_op = opcode::ReadFixed::new(
                types::Fd(fd),
                rx_pool.buffers[idx].data.get() as *mut u8,
                BUFFER_SIZE as _,
                idx as _,
            )
            .build()
            .user_data(idx as u64);

            unsafe { sq.push(&read_op)? };
            rx_pool.buffers[idx].state.store(1, Ordering::Release);
        }
    }

    let in_flight_reads = AtomicUsize::new(rx_len);

    loop {
        ring.submit_and_wait(1)?;

        let mut reads_to_resubmit = false;
        for cqe in unsafe { ring.completion_shared() } {
            let user_data = cqe.user_data() as usize;
            let result = cqe.result();

            if user_data < rx_len {
                let idx = user_data;
                in_flight_reads.fetch_sub(1, Ordering::Release);

                if result > 0 {
                    rx_pool.buffers[idx]
                        .length
                        .store(result as u32, Ordering::Release);
                    rx_pool.buffers[idx].state.store(2, Ordering::Release);

                    // Check if we need to resubmit batch
                    if in_flight_reads.load(Ordering::Acquire) < (rx_len / 4) {
                        reads_to_resubmit = true;
                    }
                } else {
                    // Error or EOF case for read
                    rx_pool.buffers[idx].state.store(0, Ordering::Release);
                    reads_to_resubmit = true;
                    if result < 0 {
                        tracing::error!(
                            "Read operation failed: {}",
                            std::io::Error::from_raw_os_error(-result)
                        );
                        metrics::tun_iouring_rx_err();
                    }
                }
            } else {
                // Write completion
                let tx_idx = user_data - rx_len;
                if result <= 0 {
                    tracing::error!(
                        "Write operation failed: {}",
                        std::io::Error::from_raw_os_error(-result)
                    );
                    metrics::tun_iouring_tx_err();
                }
                tx_pool.buffers[tx_idx].state.store(0, Ordering::Release);
            }
        }

        // Batch resubmit of reads if needed
        if reads_to_resubmit {
            let _guard = submission_lock.lock();
            let mut sq = unsafe { ring.submission_shared() };

            for idx in 0..rx_len {
                if rx_pool.buffers[idx].state.load(Ordering::Acquire) == 0 {
                    let read_op = opcode::ReadFixed::new(
                        types::Fd(fd),
                        rx_pool.buffers[idx].data.get() as *mut u8,
                        BUFFER_SIZE as _,
                        idx as _,
                    )
                    .build()
                    .user_data(idx as u64);

                    if unsafe { sq.push(&read_op) }.is_ok() {
                        rx_pool.buffers[idx].state.store(1, Ordering::Release);
                        in_flight_reads.fetch_add(1, Ordering::Release);
                    }
                }
            }
        }
    }
}
