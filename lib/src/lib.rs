extern crate prost;
extern crate bytes;
extern crate tower_grpc;

pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/rolodex.rs"));
}
