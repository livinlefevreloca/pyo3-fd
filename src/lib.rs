use libc::dup;
use pyo3::prelude::*;
use pyo3::PyObject;
use std::os::fd;
use std::os::fd::FromRawFd;
use std::os::fd::RawFd;
use thiserror::Error as ThisError;

/// Python type string constants
/// These are the string representations of the Python
/// types that we need to check for when converting
const SOCKET: &str = "socket";
const FILE_TYPES: [&str; 4] = [
    "TextIOWrapper",
    "BufferedRandom",
    "BufferedReader",
    "BufferedWriter",
];

/// Socket family constants
const AF_UNIX: i32 = 1;
const AF_INET: i32 = 2;
// const AF_INET6: i32 = 30;

/// Socket type constants
const SOCK_STREAM: i32 = 1;
const SOCK_DGRAM: i32 = 2;

/// Error types
#[derive(Debug, ThisError)]
pub enum Error {
    #[error("{0}")]
    Error(String),
    #[error("PyErr: {0}")]
    PyError(#[from] PyErr),
}

/// A trait used to define behavior for converting a Python file like object to a Rust file like object.
///
/// SAFETY: dup will create a new file descriptor that is a copy of the original.
/// **This is not a separate reference to the file**. The file descriptors still share
/// the same stateful properties such as the file offset and file status flags. We need
/// to call dup here to ensure that the file descriptor owned by the Python object is
/// not closed when our F object is dropped.
///
/// This trait offers two methods, `from_py_fd_unchecked` and `from_py_fd`. The former
/// is unsafe because the caller is responsible for ensuring that the correct rust type
/// is being created from the Python object. The latter is safe as it fill perform
/// additional checks to ensure that the Python object is of the correct type for the
/// Rust object being created.
trait FromPyFileObject: FromRawFd + Sized {
    unsafe fn from_py_fd_unchecked(obj: &PyObject) -> Result<Self, Error> {
        let pyfd = Python::with_gil(|py| {
            if let Some(fileno) = obj.getattr(py, "fileno").ok() {
                fileno
                    .call0(py)?
                    .extract::<fd::RawFd>(py)
                    .map_err(|e| Error::PyError(e))
            } else {
                Err(Error::PyError(PyErr::new::<
                    pyo3::exceptions::PyAttributeError,
                    _,
                >("No fileno attribute")))
            }
        })?;
        let duped: fd::RawFd = dup(pyfd);
        if duped < 0 {
            return Err(Error::Error(
                "Failed to duplicate file descriptor".to_string(),
            ));
        }
        let f = <Self as FromRawFd>::from_raw_fd(duped);
        Ok(f)
    }

    fn from_py_fd(obj: &PyObject) -> Result<Self, Error>;
}

/// Helper function to get the name of the Python type of an object
fn get_py_type_name(obj: &PyObject) -> Result<String, Error> {
    Python::with_gil(|py| {
        let class = obj.getattr(py, "__class__")?;
        let name: Py<_> = class.getattr(py, "__name__")?;
        name.extract::<String>(py).map_err(|e| Error::PyError(e))
    })
}

/// Helper function to get the file descriptor from a Python file like object
fn get_py_fd(obj: &PyObject) -> Result<RawFd, Error> {
    Python::with_gil(|py| {
        let fileno = obj.getattr(py, "fileno")?;
        fileno
            .call0(py)?
            .extract::<RawFd>(py)
            .map_err(|e| Error::PyError(e))
    })
}

macro_rules! impl_from_py_fd {
    ($t:ty, $verify:ident) => {
        impl FromPyFileObject for $t {
            fn from_py_fd(obj: &PyObject) -> Result<Self, Error> {
                Python::with_gil(|py| {
                    let typ = get_py_type_name(obj)?;
                    let family = obj.getattr(py, "family")?.extract::<i32>(py)?;
                    let socktype = obj.getattr(py, "type")?.extract::<i32>(py)?;
                    let fd = get_py_fd(obj)?;
                    $verify(fd, typ, family, socktype)
                })?;
                unsafe { <$t as FromPyFileObject>::from_py_fd_unchecked(obj) }
            }
        }
    };
}

/// Verify the characteristics of a TCP socket object
fn verify_tcp_stream(fd: RawFd, typ: String, family: i32, socktype: i32) -> Result<(), Error> {
    if fd < 0 {
        return Err(Error::Error("Invalid file descriptor".to_string()));
    }
    if typ != SOCKET {
        return Err(Error::Error("Not a socket object".to_string()));
    }
    if family != AF_INET {
        return Err(Error::Error("Not an AF_INET socket".to_string()));
    }
    if socktype != SOCK_STREAM {
        return Err(Error::Error("Not a SOCK_STREAM socket".to_string()));
    }
    Ok(())
}

impl_from_py_fd!(std::net::TcpStream, verify_tcp_stream);

/// Veify the characteristics of a UDP socket object
fn verify_udp_stream(fd: RawFd, typ: String, family: i32, socktype: i32) -> Result<(), Error> {
    if fd < 0 {
        return Err(Error::Error("Invalid file descriptor".to_string()));
    }
    if typ != SOCKET {
        return Err(Error::Error("Not a socket object".to_string()));
    }
    if family != AF_INET {
        return Err(Error::Error("Not an AF_INET socket".to_string()));
    }
    if socktype != SOCK_DGRAM {
        return Err(Error::Error("Not a SOCK_DGRAM socket".to_string()));
    }
    Ok(())
}

impl_from_py_fd!(std::net::UdpSocket, verify_udp_stream);

/// Verify the characteristics of a Unix Datagram socket object
fn verify_unix_datagram(fd: RawFd, typ: String, family: i32, socktype: i32) -> Result<(), Error> {
    if fd < 0 {
        return Err(Error::Error("Invalid file descriptor".to_string()));
    }
    if typ != SOCKET {
        return Err(Error::Error("Not a socket object".to_string()));
    }
    if family != AF_UNIX {
        return Err(Error::Error("Not an AF_UNIX socket".to_string()));
    }
    if socktype != SOCK_DGRAM {
        return Err(Error::Error("Not a SOCK_DGRAM socket".to_string()));
    }
    Ok(())
}

impl_from_py_fd!(std::os::unix::net::UnixDatagram, verify_unix_datagram);

/// Verify the characteristics of a Unix Stream socket object
fn verify_unix_stream(fd: RawFd, typ: String, family: i32, socktype: i32) -> Result<(), Error> {
    if fd < 0 {
        return Err(Error::Error("Invalid file descriptor".to_string()));
    }
    if typ != SOCKET {
        return Err(Error::Error("Not a socket object".to_string()));
    }
    if family != AF_UNIX {
        return Err(Error::Error("Not an AF_UNIX socket".to_string()));
    }
    if socktype != SOCK_STREAM {
        return Err(Error::Error("Not a SOCK_STREAM socket".to_string()));
    }
    Ok(())
}

impl_from_py_fd!(std::os::unix::net::UnixStream, verify_unix_stream);

/// Verify the characteristics of a file object
fn verify_file(fd: RawFd, typ: &str, additional_file_types: Option<&[&str]>) -> Result<(), Error> {
    if fd < 0 {
        return Err(Error::Error("Invalid file descriptor".to_string()));
    }

    if FILE_TYPES.contains(&typ) {
        return Ok(());
    }

    if let Some(additional_file_types) = additional_file_types {
        if additional_file_types.contains(&typ) {
            return Ok(());
        }
    }

    Err(Error::Error("Not a file object".to_string()))
}

impl FromPyFileObject for std::fs::File {
    fn from_py_fd(obj: &PyObject) -> Result<Self, Error> {
        let typ = get_py_type_name(obj)?;
        let fd = get_py_fd(obj)?;
        verify_file(fd, &typ, None)?;
        unsafe { std::fs::File::from_py_fd_unchecked(obj) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pyo3::types::PyTuple;
    use std::fs::File;
    use std::io::{Read, Write};
    use std::net::{TcpStream, UdpSocket};
    use std::os::unix::net::{UnixDatagram, UnixStream};
    use std::thread;

    fn start_tcp_server(port: u16) {
        thread::spawn(move || -> std::io::Result<()> {
            let address = format!("127.0.0.1:{port}");
            let listener = std::net::TcpListener::bind(address).unwrap();
            while let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0; 20];
                let n = stream.read(&mut buf)?;
                let mut echo = Vec::new();
                echo.extend_from_slice("echo: ".as_bytes());
                echo.extend_from_slice(&buf[..n]);
                stream.write_all(&echo)?;
                break;
            }
            Ok(())
        });
    }

    fn open_udp_socket(port: u16) {
        thread::spawn(move || -> std::io::Result<()> {
            let address = format!("127.0.0.1:{port}");
            let socket = UdpSocket::bind(address)?;
            let mut buf = [0; 20];
            let (amt, src) = socket.recv_from(&mut buf)?;
            let mut echo = Vec::new();
            echo.extend_from_slice("echo: ".as_bytes());
            echo.extend_from_slice(&buf[..amt]);
            socket.send_to(&echo, &src)?;
            Ok(())
        });
    }

    #[test]
    fn test_raw_from_py_file() {
        pyo3::prepare_freethreaded_python();
        let stdout_obj: PyObject = Python::with_gil(|py| {
            let sys = py.import("sys").unwrap();
            let stdout = sys.getattr("stdout").unwrap();
            stdout.to_object(py)
        });
        let stdout_res = unsafe { File::from_py_fd_unchecked(&stdout_obj) };

        assert!(stdout_res.is_ok());
        let mut stdout: File = stdout_res.unwrap();
        assert!(stdout.write_all(b"Hello, world!\n").is_ok());
    }

    #[test]
    fn test_raw_from_py_unix_sock_dgram() {
        pyo3::prepare_freethreaded_python();
        let (tx_obj, rx_obj): (PyObject, PyObject) = Python::with_gil(|py| {
            let socket = py.import("socket").unwrap();
            let socket_pair = socket.getattr("socketpair").unwrap();
            let pair = socket_pair.call1((AF_UNIX, SOCK_DGRAM, 0)).unwrap();
            let (tx, rx) = (pair.get_item(0).unwrap(), pair.get_item(1).unwrap());
            (tx.to_object(py), rx.to_object(py))
        });
        let (tx_res, rx_res) = unsafe {
            (
                UnixDatagram::from_py_fd_unchecked(&tx_obj),
                UnixDatagram::from_py_fd_unchecked(&rx_obj),
            )
        };

        assert!(tx_res.is_ok());
        assert!(rx_res.is_ok());
        let (tx, rx) = (tx_res.unwrap(), rx_res.unwrap());
        assert!(tx.send(b"Hello, world!\n").is_ok());
        let mut buf = [0; 14];
        assert!(rx.recv(&mut buf).is_ok());
        assert_eq!(&buf, b"Hello, world!\n");
    }

    #[test]
    fn test_raw_from_py_unix_sock_stream() {
        pyo3::prepare_freethreaded_python();
        let (tx_obj, rx_obj): (PyObject, PyObject) = Python::with_gil(|py| {
            let socket = py.import("socket").unwrap();
            let socket_pair = socket.getattr("socketpair").unwrap();
            let pair = socket_pair.call0().unwrap();
            let (tx, rx) = (pair.get_item(0).unwrap(), pair.get_item(1).unwrap());
            (tx.to_object(py), rx.to_object(py))
        });
        let (tx_res, rx_res) = unsafe {
            (
                UnixStream::from_py_fd_unchecked(&tx_obj),
                UnixStream::from_py_fd_unchecked(&rx_obj),
            )
        };

        assert!(tx_res.is_ok());
        assert!(rx_res.is_ok());
        let (mut tx, mut rx) = (tx_res.unwrap(), rx_res.unwrap());
        assert!(tx.write_all(b"Hello, world!\n").is_ok());
        let mut buf = [0; 14];
        assert!(rx.read_exact(&mut buf).is_ok());
        assert_eq!(&buf, b"Hello, world!\n");
    }

    #[test]
    fn test_raw_from_py_tcp_sock_stream() {
        pyo3::prepare_freethreaded_python();
        start_tcp_server(1337);
        let sock_obj: PyObject = Python::with_gil(|py| {
            let socket = py.import("socket").unwrap();
            let sock = socket.getattr("socket").unwrap();
            let created_sock = sock.call1((AF_INET, SOCK_STREAM, 0)).unwrap();
            let connect = created_sock.getattr("connect").unwrap();
            let raw_addr = ("127.0.0.1", 1337);
            let addr = raw_addr.to_object(py);
            let args = PyTuple::new(py, &[addr]);
            connect.call(args, None).unwrap();
            created_sock.to_object(py)
        });

        let stream_res = unsafe { TcpStream::from_py_fd_unchecked(&sock_obj) };
        assert!(stream_res.is_ok());
        let mut stream = stream_res.unwrap();
        assert!(stream.write_all(b"Hello, world!\n").is_ok());
        let mut buf = [0; 20];
        assert!(stream.read_exact(&mut buf).is_ok());
        assert_eq!(&buf, b"echo: Hello, world!\n");
    }

    #[test]
    fn test_raw_from_py_udp_sock_dgram() {
        pyo3::prepare_freethreaded_python();
        open_udp_socket(1338);
        let sock_obj: PyObject = Python::with_gil(|py| {
            let socket = py.import("socket").unwrap();
            let sock = socket.getattr("socket").unwrap();
            let created_sock = sock.call1((AF_INET, SOCK_DGRAM, 0)).unwrap();
            let connect = created_sock.getattr("connect").unwrap();
            let raw_addr = ("127.0.0.1", 1338);
            let addr = raw_addr.to_object(py);
            let args = PyTuple::new(py, &[addr]);
            connect.call(args, None).unwrap();
            created_sock.to_object(py)
        });

        let dgram_res = unsafe { UdpSocket::from_py_fd_unchecked(&sock_obj) };
        assert!(dgram_res.is_ok());
        let dgram = dgram_res.unwrap();
        assert!(dgram.send(b"Hello, world!\n").is_ok());
        let mut buf = [0; 20];
        assert!(dgram.recv(&mut buf).is_ok());
        assert_eq!(&buf, b"echo: Hello, world!\n");
    }

    #[test]
    fn test_from_py_file() {
        pyo3::prepare_freethreaded_python();
        let stdout_obj: PyObject = Python::with_gil(|py| {
            let sys = py.import("sys").unwrap();
            let stdout = sys.getattr("stdout").unwrap();
            stdout.to_object(py)
        });
        let stdout_res = File::from_py_fd(&stdout_obj);

        assert!(stdout_res.is_ok());
        let mut stdout: File = stdout_res.unwrap();
        assert!(stdout.write_all(b"Hello, world!\n").is_ok());
    }

    #[test]
    fn test_from_py_file_fail() {
        pyo3::prepare_freethreaded_python();
        let tx_obj: PyObject = Python::with_gil(|py| {
            let socket = py.import("socket").unwrap();
            let socket_pair = socket.getattr("socketpair").unwrap();
            let pair = socket_pair.call1((AF_UNIX, SOCK_DGRAM, 0)).unwrap();
            let (tx, _) = (pair.get_item(0).unwrap(), pair.get_item(1).unwrap());
            tx.to_object(py)
        });
        let file_res = File::from_py_fd(&tx_obj);
        assert!(!file_res.is_ok());
    }

    #[test]
    fn test_from_py_unix_sock_dgram() {
        pyo3::prepare_freethreaded_python();
        let (tx_obj, rx_obj): (PyObject, PyObject) = Python::with_gil(|py| {
            let socket = py.import("socket").unwrap();
            let socket_pair = socket.getattr("socketpair").unwrap();
            let pair = socket_pair.call1((AF_UNIX, SOCK_DGRAM, 0)).unwrap();
            let (tx, rx) = (pair.get_item(0).unwrap(), pair.get_item(1).unwrap());
            (tx.to_object(py), rx.to_object(py))
        });
        let (tx_res, rx_res) = (
            UnixDatagram::from_py_fd(&tx_obj),
            UnixDatagram::from_py_fd(&rx_obj),
        );

        assert!(tx_res.is_ok());
        assert!(rx_res.is_ok());
        let (tx, rx) = (tx_res.unwrap(), rx_res.unwrap());
        assert!(tx.send(b"Hello, world!\n").is_ok());
        let mut buf = [0; 14];
        assert!(rx.recv(&mut buf).is_ok());
        assert_eq!(&buf, b"Hello, world!\n");
    }

    #[test]
    fn test_from_py_unix_sock_dgram_fail() {
        pyo3::prepare_freethreaded_python();
        let stdout_obj: PyObject = Python::with_gil(|py| {
            let sys = py.import("sys").unwrap();
            let stdout = sys.getattr("stdout").unwrap();
            stdout.to_object(py)
        });

        let stdout_res = UnixDatagram::from_py_fd(&stdout_obj);
        assert!(!stdout_res.is_ok());
    }

    #[test]
    fn test_from_py_unix_sock_stream() {
        pyo3::prepare_freethreaded_python();
        let (tx_obj, rx_obj): (PyObject, PyObject) = Python::with_gil(|py| {
            let socket = py.import("socket").unwrap();
            let socket_pair = socket.getattr("socketpair").unwrap();
            let pair = socket_pair.call0().unwrap();
            let (tx, rx) = (pair.get_item(0).unwrap(), pair.get_item(1).unwrap());
            (tx.to_object(py), rx.to_object(py))
        });
        let (tx_res, rx_res) = (
            UnixStream::from_py_fd(&tx_obj),
            UnixStream::from_py_fd(&rx_obj),
        );

        assert!(tx_res.is_ok());
        assert!(rx_res.is_ok());
        let (mut tx, mut rx) = (tx_res.unwrap(), rx_res.unwrap());
        assert!(tx.write_all(b"Hello, world!\n").is_ok());
        let mut buf = [0; 14];
        assert!(rx.read_exact(&mut buf).is_ok());
        assert_eq!(&buf, b"Hello, world!\n");
    }

    #[test]
    fn test_from_py_unix_sock_stream_fail() {
        pyo3::prepare_freethreaded_python();
        let stdout_obj: PyObject = Python::with_gil(|py| {
            let sys = py.import("sys").unwrap();
            let stdout = sys.getattr("stdout").unwrap();
            stdout.to_object(py)
        });

        let stdout_res = UnixStream::from_py_fd(&stdout_obj);
        assert!(!stdout_res.is_ok());
    }

    #[test]
    fn test_from_py_tcp_sock_stream() {
        pyo3::prepare_freethreaded_python();
        start_tcp_server(1339);
        let sock_obj: PyObject = Python::with_gil(|py| {
            let socket = py.import("socket").unwrap();
            let sock = socket.getattr("socket").unwrap();
            let created_sock = sock.call1((AF_INET, SOCK_STREAM, 0)).unwrap();
            let connect = created_sock.getattr("connect").unwrap();
            let raw_addr = ("127.0.0.1", 1339);
            let addr = raw_addr.to_object(py);
            let args = PyTuple::new(py, &[addr]);
            connect.call(args, None).unwrap();
            created_sock.to_object(py)
        });

        let stream_res = TcpStream::from_py_fd(&sock_obj);
        assert!(stream_res.is_ok());
        let mut stream = stream_res.unwrap();
        assert!(stream.write_all(b"Hello, world!\n").is_ok());
        let mut buf = [0; 20];
        assert!(stream.read_exact(&mut buf).is_ok());
        assert_eq!(&buf, b"echo: Hello, world!\n");
    }

    #[test]
    fn test_from_py_tcp_sock_stream_fail() {
        pyo3::prepare_freethreaded_python();
        let stdout_obj: PyObject = Python::with_gil(|py| {
            let sys = py.import("sys").unwrap();
            let stdout = sys.getattr("stdout").unwrap();
            stdout.to_object(py)
        });

        let stdout_res = TcpStream::from_py_fd(&stdout_obj);
        assert!(!stdout_res.is_ok());
    }

    #[test]
    fn test_from_py_udp_sock_dgram() {
        pyo3::prepare_freethreaded_python();
        open_udp_socket(1340);
        let sock_obj: PyObject = Python::with_gil(|py| {
            let socket = py.import("socket").unwrap();
            let sock = socket.getattr("socket").unwrap();
            let created_sock = sock.call1((AF_INET, SOCK_DGRAM, 0)).unwrap();
            let connect = created_sock.getattr("connect").unwrap();
            let raw_addr = ("127.0.0.1", 1340);
            let addr = raw_addr.to_object(py);
            let args = PyTuple::new(py, &[addr]);
            connect.call(args, None).unwrap();
            created_sock.to_object(py)
        });

        let dgram_res = UdpSocket::from_py_fd(&sock_obj);
        assert!(dgram_res.is_ok());
        let dgram = dgram_res.unwrap();
        assert!(dgram.send(b"Hello, world!\n").is_ok());
        let mut buf = [0; 20];
        assert!(dgram.recv(&mut buf).is_ok());
        assert_eq!(&buf, b"echo: Hello, world!\n");
    }

    #[test]
    fn test_from_py_udp_sock_dgram_fail() {
        pyo3::prepare_freethreaded_python();
        let stdout_obj: PyObject = Python::with_gil(|py| {
            let sys = py.import("sys").unwrap();
            let stdout = sys.getattr("stdout").unwrap();
            stdout.to_object(py)
        });

        let stdout_res = UdpSocket::from_py_fd(&stdout_obj);
        assert!(!stdout_res.is_ok());
    }
}
