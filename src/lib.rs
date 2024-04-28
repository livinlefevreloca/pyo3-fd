use libc::dup;
use pyo3::prelude::*;
use pyo3::PyObject;
use std::os::fd::{FromRawFd, RawFd};
use std::fs::File;
use std::net::{TcpStream, UdpSocket};
use std::os::unix::net::{UnixDatagram, UnixStream};
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

/// A trait to implement for wrapping types that represent Python file like objects.
/// These types can then be used to implement the `FromPyFileObject` trait to convert
/// the Python object to a Rust file like object.
///
/// use pyo3::prelude::*;
/// use pyo3::PyObject;
/// use std::net::TcpStream;
///
/// struct ProcessStdout {
///    obj: PyObject,
/// }
///
/// impl ProcessStdout {
///     pub fn new(obj: PyObject) -> Self {
///         Self { obj }
///     }
/// }
///
/// impl pyo3_fd::PyFileObject for ProcessStdout {
///     fn verify(&self) -> Result<(), pyo3_fd::Error> {
///         let typ = pyo3_fd::get_py_type_name(self.as_object())?;
///         if typ != "BufferedReader" {
///             return Err(pyo3_fd::Error::Error("Not a ProcessStdout object".to_string()));
///         }
///         Ok(())
///     }
///     fn as_object(&self) -> &PyObject {
///         &(*self).obj
///     }
/// }
///
/// impl pyo3_fd::FromPyFileObject<ProcessStdout> for UnixStream {}
pub trait PyFileObject {
    fn fileno(&self) -> Result<RawFd, Error> {
        get_py_fd(self.as_object())
    }

    fn verify(&self) -> Result<(), Error> {
        Ok(())
    }

    fn as_object(&self) -> &PyObject;
}


/// A trait used to define behavior for converting a Python file like object to a Rust file like object.
///
/// SAFETY: dup will create a new file descriptor that is a copy of the original.
/// **This is not a separate reference to the file**. The file descriptors still share
/// the same stateful properties such as the file offset and file status flags. We need
/// to call dup here to ensure that the file descriptor owned by the Python object is
/// not closed when our F object is dropped.
///
/// This trait offers two methods, `try_from_py_fd_unchecked` and `try_from_py_fd`. The former
/// is unsafe because the caller is responsible for ensuring that the correct rust type
/// is being created from the Python object. The latter is meant to safe as it will perform
/// additional checks to ensure that the Python object is of the correct type for the
/// Rust object being created. However the checks are still the responsibility of the implementor
/// Since the type from which the file descriptor is being duplicated is
/// only known by the implementor.
trait FromPyFileObject<Input>: FromRawFd + Sized
where Input: PyFileObject
{
    unsafe fn try_from_py_fd_unchecked(input: Input) -> Result<Self, Error> {
        let pyfd = Python::with_gil(|_| input.fileno())?;
        let duped: RawFd = dup(pyfd);
        if duped < 0 {
            return Err(Error::Error(
                "Failed to duplicate file descriptor".to_string(),
            ));
        }
        let f = <Self as FromRawFd>::from_raw_fd(duped);
        Ok(f)
    }

    fn try_from_py_fd(input: Input) -> Result<Self, Error> {
        input.verify()?;
        unsafe { <Self as FromPyFileObject<_>>::try_from_py_fd_unchecked(input) }
    }
}

// Helper functions for various operations dealing with Python objects

/// Helper function to get the name of the Python type of an object
pub fn get_py_type_name(obj: &PyObject) -> Result<String, Error> {
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

/// Helper function to extract socket characteristics from a Python socket object
fn get_sock_characteristics(obj: &PyObject) -> Result<(RawFd, String, i32, i32), Error> {
    Python::with_gil(|py| {
        let fileno = obj.getattr(py, "fileno")?;
        let fd: RawFd = fileno.call0(py)?.extract::<RawFd>(py)?;
        let family: i32 = obj.getattr(py, "family")?.extract::<i32>(py)?;
        let socktype: i32 = obj.getattr(py, "type")?.extract::<i32>(py)?;
        let typ = get_py_type_name(obj)?;
        Ok((fd, typ, family, socktype))
    })
}


/// Implement the PyFileObject trait for a given wrapper type using the provided verification function
macro_rules! impl_py_file_object {
    ($input:ident, $f:ident) => {
        pub struct $input {
            obj: PyObject,
        }

        impl $input {
            pub fn new(obj: PyObject) -> Self {
                Self { obj }
            }
        }

        impl PyFileObject for $input {
            fn as_object(&self) -> &PyObject {
                &(*self).obj
            }

            fn verify(&self) -> Result<(), Error> {
                $f(self)
            }
        }
    };
}


/// Verify the characteristics of a Unix Datagram socket object
fn verify_unix_datagram<O: PyFileObject>(obj: &O) -> Result<(), Error> {
    let (fd, typ, family, socktype) = get_sock_characteristics(obj.as_object())?;
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

impl_py_file_object!(PyUnixDatagramSocket, verify_unix_datagram);


/// Verify the characteristics of a Unix Stream socket object
fn verify_unix_stream<O: PyFileObject>(obj: &O) -> Result<(), Error> {
    let (fd, typ, family, socktype) = get_sock_characteristics(obj.as_object())?;
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

impl_py_file_object!(PyUnixStreamSocket, verify_unix_stream);


/// Verify the characteristics of a TCP socket object
fn verify_tcp_stream<O: PyFileObject>(obj: &O) -> Result<(), Error> {
    let (fd, typ, family, socktype) = get_sock_characteristics(obj.as_object())?;
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

impl_py_file_object!(PyTcpStreamSocket, verify_tcp_stream);


/// Veify the characteristics of a UDP socket object
fn verify_udp_stream<O: PyFileObject>(obj: &O) -> Result<(), Error> {
    let (fd, typ, family, socktype) = get_sock_characteristics(obj.as_object())?;
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

impl_py_file_object!(PyUdpSocket, verify_udp_stream);


/// Verify the characteristics of a file object
fn verify_file<O: PyFileObject>(obj: &O) -> Result<(), Error> {
    let obj = obj.as_object();
    let typ = get_py_type_name(obj)?;
    let fd = get_py_fd(obj)?;
    if fd < 0 {
        return Err(Error::Error("Invalid file descriptor".to_string()));
    }

    if FILE_TYPES.contains(&typ.as_str()) {
        return Ok(());
    }

    Err(Error::Error("Not a file object".to_string()))
}

impl_py_file_object!(PyFile, verify_file);


impl FromPyFileObject<PyUnixDatagramSocket> for UnixDatagram {}
impl FromPyFileObject<PyUnixStreamSocket> for UnixStream {}
impl FromPyFileObject<PyTcpStreamSocket> for TcpStream {}
impl FromPyFileObject<PyUdpSocket> for UdpSocket {}
impl FromPyFileObject<PyFile> for File {}


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

        let input = PyFile::new(stdout_obj);
        let stdout_res = unsafe { File::try_from_py_fd_unchecked(input) };

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

        let tx_input = PyUnixDatagramSocket::new(tx_obj);
        let rx_input = PyUnixDatagramSocket::new(rx_obj);

        let (tx_res, rx_res) = unsafe {
            (
                UnixDatagram::try_from_py_fd_unchecked(tx_input),
                UnixDatagram::try_from_py_fd_unchecked(rx_input),
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

        let tx_input = PyUnixStreamSocket::new(tx_obj);
        let rx_input = PyUnixStreamSocket::new(rx_obj);

        let (tx_res, rx_res) = unsafe {
            (
                UnixStream::try_from_py_fd_unchecked(tx_input),
                UnixStream::try_from_py_fd_unchecked(rx_input),
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

        let input = PyTcpStreamSocket::new(sock_obj);

        let stream_res = unsafe { TcpStream::try_from_py_fd_unchecked(input) };
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

        let input = PyUdpSocket::new(sock_obj);

        let dgram_res = unsafe { UdpSocket::try_from_py_fd_unchecked(input) };
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

        let input = PyFile::new(stdout_obj);
        let stdout_res = File::try_from_py_fd(input);

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

        let input = PyFile::new(tx_obj);
        let file_res = File::try_from_py_fd(input);
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

        let tx_input = PyUnixDatagramSocket::new(tx_obj);
        let rx_input = PyUnixDatagramSocket::new(rx_obj);

        let (tx_res, rx_res) = (
            UnixDatagram::try_from_py_fd(tx_input),
            UnixDatagram::try_from_py_fd(rx_input),
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

        let input = PyUnixDatagramSocket::new(stdout_obj);

        let stdout_res = UnixDatagram::try_from_py_fd(input);
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

        let tx_input = PyUnixStreamSocket::new(tx_obj);
        let rx_input = PyUnixStreamSocket::new(rx_obj);

        let (tx_res, rx_res) = (
            UnixStream::try_from_py_fd(tx_input),
            UnixStream::try_from_py_fd(rx_input),
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

        let input = PyUnixStreamSocket::new(stdout_obj);

        let stdout_res = UnixStream::try_from_py_fd(input);
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

        let input = PyTcpStreamSocket::new(sock_obj);

        let stream_res = TcpStream::try_from_py_fd(input);
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

        let input = PyTcpStreamSocket::new(stdout_obj);

        let stdout_res = TcpStream::try_from_py_fd(input);
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

        let input = PyUdpSocket::new(sock_obj);

        let dgram_res = UdpSocket::try_from_py_fd(input);
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

        let input = PyUdpSocket::new(stdout_obj);

        let stdout_res = UdpSocket::try_from_py_fd(input);
        assert!(!stdout_res.is_ok());
    }
}
