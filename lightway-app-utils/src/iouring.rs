use crate::metrics;
use anyhow::Result;
use bytes::BytesMut;
use io_uring::{IoUring, opcode, types};
use libc::iovec;
use lightway_core::IOCallbackResult;
use parking_lot::Mutex;
use std::{
    os::unix::io::{AsRawFd, RawFd},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::Duration,
};
use tokio::sync::Notify;
use tokio_eventfd::EventFd;

#[repr(u64)]
enum IOUringActionID {
    RecycleBuffers = 0x10001000,
    ReceivedBuffer = 0xfeedfeed,
    RecyclePending = 0xdead1000,
}
const RX_BUFFER_GROUP: u16 = 0xdead;

/// Wrapper for raw pointer that guarantees Send + Sync safety
/// Safety: The underlying memory is owned by the Arc'd BufferPool and outlives any pointer usage
struct BufferPtr(*mut u8);
#[allow(unsafe_code)]
unsafe impl Send for BufferPtr {}
#[allow(unsafe_code)]
unsafe impl Sync for BufferPtr {}

impl BufferPtr {
    fn as_ptr(&self) -> *mut u8 {
        self.0
    }
}

struct BufferPool {
    data: Vec<u8>, // contiguous block of memory (all buffers)
    lengths: Vec<AtomicUsize>,
    states: Vec<AtomicBool>, // 0 (false) = free, 1 (true) = in-use
    usage_idx: AtomicUsize,
    buffer_size: usize,
}

impl BufferPool {
    fn new(entry_size: usize, pool_size: usize) -> Self {
        // Ensure BUFFER_SIZE is multiple of 128-bit/16-byte (less cache-miss)
        let buffer_size = (entry_size + 15) & !15;

        Self {
            data: vec![0u8; buffer_size * pool_size],
            lengths: (0..pool_size).map(|_| AtomicUsize::new(0)).collect(),
            states: (0..pool_size).map(|_| AtomicBool::new(false)).collect(),
            usage_idx: AtomicUsize::new(0),
            buffer_size,
        }
    }

    fn get_buffer(&self, idx: usize) -> (BufferPtr, &AtomicUsize, &AtomicBool) {
        #[allow(unsafe_code)]
        let ptr = unsafe { self.data.as_ptr().add(idx * self.buffer_size) as *mut u8 };

        (BufferPtr(ptr), &self.lengths[idx], &self.states[idx])
    }
}

/// IO-uring Struct
pub struct IOUring<T: AsRawFd> {
    owned_fd: Arc<T>,
    rx_pool: Arc<BufferPool>,
    tx_pool: Arc<BufferPool>,
    rx_notify: Arc<Notify>,
    rx_eventfd: EventFd,
    rx_provide_buffers: Arc<AtomicBool>,
    ring: Arc<IoUring>,
    submission_lock: Arc<Mutex<()>>,
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
        // NOTE: it's probably a good idea for now to allocate rx/tx/ring at the same size
        //  this is because the VPN use-case usually has MTU-sized buffers going in-and-out

        let rx_pool = Arc::new(BufferPool::new(mtu, ring_size));
        let tx_pool = Arc::new(BufferPool::new(mtu, ring_size));

        let ring = Arc::new(
            IoUring::builder()
                .setup_sqpoll(sqpoll_idle_time.as_millis() as u32)
                .build(ring_size as u32)?,
        );

        let rx_notify = Arc::new(Notify::new());
        let rx_eventfd = EventFd::new(0, false)?;
        let rx_provide_buffers = Arc::new(AtomicBool::new(false));

        // NOTE: for now this ensures we only create 1 kthread per tunnel, and not 2 (rx/tx)
        //  we can opt to change this going forward, or redo the structure to not need a lock
        let submission_lock = Arc::new(Mutex::new(()));

        // We can provide the buffers without a lock, as we still havn't shared the ownership
        let fd = owned_fd.as_raw_fd();
        unsafe {
            let mut sq = ring.submission_shared();
            sq.push(
                &opcode::ProvideBuffers::new(
                    rx_pool.data.as_ptr() as *mut u8,
                    mtu as i32,
                    ring_size as u16,
                    RX_BUFFER_GROUP,
                    0,
                )
                .build()
                .user_data(IOUringActionID::RecycleBuffers as u64),
            )?;
            sq.push(
                &opcode::RecvMulti::new(types::Fd(fd), RX_BUFFER_GROUP)
                    .build()
                    .user_data(IOUringActionID::ReceivedBuffer as u64),
            )?;

            // A bit ineffective vs. calculate offset directly, but more maintainable
            let tx_iovecs: Vec<_> = (0..ring_size)
                .map(|idx| {
                    let (ptr, _, _) = tx_pool.get_buffer(idx);
                    iovec {
                        iov_base: ptr.as_ptr() as *mut libc::c_void,
                        iov_len: mtu,
                    }
                })
                .collect();
            ring.submitter().register_buffers(&tx_iovecs)?;
        }

        let rx_pool_clone = rx_pool.clone();
        let tx_pool_clone = tx_pool.clone();
        let ring_clone = ring.clone();
        let lock_clone = submission_lock.clone();
        let notify_clone = rx_notify.clone();
        let eventfd = rx_eventfd.as_raw_fd();
        let provide_buffers = rx_provide_buffers.clone();

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
                        notify_clone,
                        eventfd,
                        provide_buffers,
                        ring_clone,
                        lock_clone,
                    ))
            })?;

        Ok(Self {
            owned_fd,
            rx_pool,
            tx_pool,
            rx_notify,
            rx_eventfd,
            rx_provide_buffers,
            ring,
            submission_lock,
        })
    }

    /// Retrieve a reference to the underlying device
    pub fn owned_fd(&self) -> &T {
        &self.owned_fd
    }

    /// Send packet on Tun device (push to RING and submit)
    pub fn try_send(&self, buf: BytesMut) -> IOCallbackResult<usize> {
        // For semantics, see recv() function below
        let idx = self
            .tx_pool
            .usage_idx
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |idx| {
                Some((idx + 1) % self.rx_pool.states.len())
            })
            .unwrap();
        let (buffer, length, state) = self.tx_pool.get_buffer(idx);

        let len = buf.len();
        if len > length.load(Ordering::Relaxed) {
            return IOCallbackResult::WouldBlock;
        }

        // Check if buffer is free (state = 0)
        if state
            .compare_exchange(
                false,
                true, // free -> in-use
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

        unsafe { std::slice::from_raw_parts_mut(buffer.as_ptr(), len).copy_from_slice(&buf) };
        length.store(len, Ordering::Release);

        // NOTE: IOUringActionID values have to be bigger then the ring-size
        //  this is because we use <index> here as data for send_fixed operations
        let write_op = opcode::WriteFixed::new(
            types::Fd(self.owned_fd.as_raw_fd()),
            buffer.as_ptr(),
            len as _,
            idx as _,
        )
        .build()
        // NOTE: we set the index starting from after the RX_POOL part
        .user_data(idx as u64);

        // Safely queue submission
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
        // NOTE: Explanation on why these semantics were used:
        // Flow:
        // 1. The current value is loaded
        // 2. Our closure is called with that value
        // 3. A compare-and-swap (CAS) operation attempts to update with our new value
        //
        // The calculation of (X+1 % len) happens INSIDE closure, after the load but before the CAS.
        // So if multiple threads are running concurrently:
        // - Thread A loads value X
        // - Thread B loads value X (before A's CAS completes)
        // - Both calculate X+1 % len
        // - We need AqcRel to ensure threads don't set values on top of each-other.
        // - First thread's CAS should succeed as no value changed
        // - Second thread's CAS should fail because the value changed
        // - Second thread would retry, so we need Acquire on fetch to see Thread A's value
        let idx = self
            .rx_pool
            .usage_idx
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |idx| {
                Some((idx + 1) % self.rx_pool.states.len())
            })
            .unwrap();
        let (buffer, length, state) = self.rx_pool.get_buffer(idx);

        loop {
            // NOTE: unlike the above case, here we can use Relaxed ordering for better performance.
            // This is because we don't use the value in a closure, so we don't care for ensuring it's current value
            if state
                .compare_exchange(true, false, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                let len = length.load(Ordering::Acquire);
                let mut new_buf = BytesMut::with_capacity(len);
                unsafe {
                    new_buf.extend_from_slice(std::slice::from_raw_parts(buffer.as_ptr(), len))
                };
                return IOCallbackResult::Ok(new_buf);
            }
            // IO-Bound wait for available buffers
            self.rx_notify.notified().await;

            // Check if kernel needs more buffers (and ensure only one notification is sent)
            if self
                .rx_provide_buffers
                .compare_exchange(true, false, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                let val = 1u64;
                unsafe {
                    if libc::write(
                        self.rx_eventfd.as_raw_fd(),
                        &val as *const u64 as *const _,
                        8,
                    ) < 0
                    {
                        let err = std::io::Error::last_os_error();
                        tracing::error!("Failed to write to eventfd: {}", err);
                        // The following is a prayer to god to hopefully succeed next time around
                        self.rx_provide_buffers.store(true, Ordering::Release);
                    }
                }
            }
        }
    }
}

#[allow(unsafe_code)]
async fn iouring_task(
    tun_fd: RawFd,
    rx_pool: Arc<BufferPool>,
    tx_pool: Arc<BufferPool>,
    rx_notify: Arc<Notify>,
    rx_eventfd: RawFd,
    rx_provide_buffers: Arc<AtomicBool>,
    ring: Arc<IoUring>,
    submission_lock: Arc<Mutex<()>>,
) -> Result<()> {
    let mut eventfd_buf = [0u64; 1]; // Buffer for eventfd read (8 bytes)

    // Submit initial read for eventfd (needs to be here for buffer to be on stack of the task)
    unsafe {
        let _guard = submission_lock.lock();
        let mut sq = ring.submission_shared();
        sq.push(
            &opcode::Read::new(
                types::Fd(rx_eventfd),
                eventfd_buf.as_mut_ptr() as *mut u8,
                8,
            )
            .build()
            .user_data(IOUringActionID::RecyclePending as u64),
        )?;
    }

    loop {
        ring.submit_and_wait(1)?;

        for cqe in unsafe { ring.completion_shared() } {
            match cqe.user_data() {
                x if x == IOUringActionID::RecycleBuffers as u64 => {
                    // Buffer provision completed
                    tracing::debug!("Buffer provision completed");
                }

                x if x == IOUringActionID::RecyclePending as u64 => {
                    if cqe.result() > 0 {
                        // Got notification we need more buffers
                        // NOTE: This approach is very good for cases we have constant data-flow
                        //  we can only load the buffers for kernel when our read-threads are done with existing data,
                        //  if our read-threads would block for too long elsewhere it would back-pressure the NIF device
                        let _guard = submission_lock.lock();
                        unsafe {
                            let mut sq = ring.submission_shared();

                            // Make sure kernel can use all buffers again
                            sq.push(
                                &opcode::ProvideBuffers::new(
                                    rx_pool.data.as_ptr() as *mut u8,
                                    rx_pool.buffer_size as i32,
                                    rx_pool.states.len() as u16,
                                    RX_BUFFER_GROUP,
                                    0,
                                )
                                .build()
                                .user_data(IOUringActionID::RecycleBuffers as u64),
                            )?;

                            sq.push(
                                &opcode::RecvMulti::new(types::Fd(tun_fd), RX_BUFFER_GROUP)
                                    .build()
                                    .user_data(IOUringActionID::ReceivedBuffer as u64),
                            )?;

                            // Resubmit eventfd read
                            sq.push(
                                &opcode::Read::new(
                                    types::Fd(rx_eventfd),
                                    eventfd_buf.as_mut_ptr() as *mut u8,
                                    8,
                                )
                                .build()
                                .user_data(IOUringActionID::RecyclePending as u64),
                            )?;
                        }
                    }
                }

                x if x == IOUringActionID::ReceivedBuffer as u64 => {
                    let result = cqe.result();
                    if result < 0 {
                        tracing::error!(
                            "Receive failed: {}",
                            std::io::Error::from_raw_os_error(-result)
                        );
                        metrics::tun_iouring_rx_err();
                        continue;
                    }

                    let buf_id = io_uring::cqueue::buffer_select(cqe.flags()).unwrap();
                    let (_, length, state) = rx_pool.get_buffer(buf_id as _);

                    length.store(result as usize, Ordering::Release);
                    state.store(true, Ordering::Release); // Mark as ready-for-user
                    rx_notify.notify_waiters();

                    if !io_uring::cqueue::more(cqe.flags()) {
                        rx_provide_buffers.store(true, Ordering::Release);
                    }
                }

                idx => {
                    // TX completion
                    let result = cqe.result();
                    if result < 0 {
                        tracing::error!(
                            "Send failed: {}",
                            std::io::Error::from_raw_os_error(-result)
                        );
                        metrics::tun_iouring_tx_err();
                    }
                    let (_, _, state) = tx_pool.get_buffer(idx as _);
                    state.store(false, Ordering::Release); // mark as available for send
                }
            }
        }
    }
}
