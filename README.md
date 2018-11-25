# rust-kres

This crate provids a safe interface for Knot Resolver library (libkres).
[libkres](https://knot-resolver.cz) is an implementation of a full DNS recursive resolver,
including cache and DNSSEC validation. It doesn't require a specific I/O model and instead provides
a generic interface for pushing/pulling DNS messages until the request is satisfied.

Example:

```rust
use std::net::{SocketAddr, UdpSocket};
use kres::{Context, Request, State};

// DNS message wire format
let question = [2, 104, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 1];
let from_addr = "127.0.0.1:1234".parse::<SocketAddr>().unwrap();

let context = Context::new();
let req = Request::new(context.clone());
let mut state = req.consume(&question, from_addr);

// Process the subrequests
while state == State::PRODUCE {
    state = match req.produce() {
        Some((msg, addr_set)) => {

            // This can be any I/O model the application uses
            let mut socket = UdpSocket::bind("0.0.0.0:0").unwrap();
            socket.send_to(&msg, &addr_set[0]).unwrap();
            let mut buf = [0; 512];
            let (amt, src) = socket.recv_from(&mut buf).unwrap();

            // Pass the response back to the request
            req.consume(&buf[..amt], src)
        },
        None => {
            break;
        }
    }
}

// Convert request into final answer
let answer = req.finish(state).unwrap();
```