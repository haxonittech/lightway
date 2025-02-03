# Usage message
if [ "$#" -ne 1 ]; then
    echo "Usage: sudo ./loss_test.sh <loss_probability_in_float>"
    exit 1
fi

# Add artifical packet loss
echo "Adding artifical packet loss..."
iptables -A INPUT --protocol udp -m statistic --mode random --probability $1 -j DROP



### ~ With Raptor ~ ###

echo "Testing with raptor"

nohup cargo run --release --example receiver > receiver_raptor.log 2>&1 &
receiver_pid=$!

echo "Running the sender..."
cargo run --release --example sender > /dev/null

echo "Sleeping for a second"
sleep 1

tail receiver_raptor.log -n 1

echo "Killing receiver process..."
kill -9 $receiver_pid



### ~ Without Raptor ~ ###

echo "Testing without raptor"

nohup cargo run --release --example receiver --features no_raptor > receiver_no_raptor.log 2>&1 &
receiver_no_raptor_pid=$!

echo "Running the sender..."
cargo run --release --example sender --features no_raptor > /dev/null

echo "Sleeping for a second"
sleep 1

tail receiver_no_raptor.log -n 1

echo "Killing receiver process..."
kill -9 $receiver_no_raptor_pid

# Remove artifical packet loss
echo "Removing artifical packet loss..."
sudo iptables -F INPUT
# Use "sudo iptables -S" to manually check if it is flushed