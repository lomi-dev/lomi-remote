// Fixed inert native child: no credentials, network, files, shell or descendants.
// Parent holds the pipe. Loss of the parent closes it; this is only a cleanup
// lifeline, never evidence permitting the host to release an uncertain lease.
fn main() {
    use std::io::Read;
    let mut byte = [0];
    while std::io::stdin().read(&mut byte).is_ok_and(|n| n != 0) {}
}
