package darkstar

import "net"

func ReadFully(conn net.Conn, buffer []byte) error {
	bytesRead, readError := conn.Read(buffer)
	if readError != nil {
		return readError
	}

	for bytesRead < len(buffer) {
		moreBytesRead, forReadError := conn.Read(buffer[bytesRead:])
		if forReadError != nil {
			return forReadError
		}

		bytesRead += moreBytesRead
	}

	return nil
}

func WriteFully(conn net.Conn, bytes []byte) error {
	bytesWritten, writeError := conn.Write(bytes)
	if writeError != nil {
		return writeError
	}

	for bytesWritten < len(bytes) {
		moreBytesWritten, forWriteError := conn.Write(bytes[bytesWritten:])
		if forWriteError != nil {
			return forWriteError
		}

		bytesWritten += moreBytesWritten
	}

	return nil
}