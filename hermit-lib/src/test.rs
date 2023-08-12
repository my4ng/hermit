use async_std::net::{TcpStream, TcpListener};

pub(crate) async fn get_test_tcp_streams(port: u16) -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind(("127.0.0.1", port)).await.unwrap();
    let stream2 = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let (stream1, _) = listener.accept().await.unwrap();

    (stream1, stream2)
}