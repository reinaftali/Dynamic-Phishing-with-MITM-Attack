import glob

IMG_LOC = r".\IMGs"
HEADER_SIZE = 10
CLIENT_BUFFER = 16

seed = '0111100110110010'


def send_msg(sock, msg):
    """
       Sends a message over the socket connection.

       :param sock: The socket connection to the server.
       :param msg: The message to be sent.
       """
    # Sending data back
    # print(msg, len(msg))

    msg_length = str(len(str(msg))).zfill(HEADER_SIZE)
    total_msg = msg_length + str(msg)

    print(total_msg)

    sock.sendall(total_msg.encode())


def recv_msg(sock):
    """
       Receives a message from the socket connection.

       :param sock: The socket connection to the server.
       :return: The received message.
       """
    # Receiving data from the server
    msg_len = sock.recv(HEADER_SIZE).decode()  # len of msg up to HEADER_SIZE digit number
    print('LEN: {}'.format(msg_len))
    msg = sock.recv(int(msg_len)).decode()

    # print(full_msg)
    return msg  # full_msg


def get_list_of_imgs(path):
    """
        Gets the list of image file paths in the specified directory.

        :param path: The path to the directory containing the images.
        :return: A list of image file paths.
        """
    return ('\n'.join(glob.glob(r'{}\*.*'.format(path)))).split("\n")


def send_photo(sock, photo_len, path):
    """
      Sends a photo over the socket connection.

      :param sock: The socket connection to the server.
      :param photo_len: The length of the photo to be sent.
      :param path: The path to the photo file.
      """
    # Sending data back
    # print(msg, len(msg))

    send_msg(sock, photo_len)

    with open(path, 'rb') as f:
        photo = f.read()

    sock.sendall(photo)


def recv_photo(sock, path):
    """
      Receives a photo from the socket connection and saves it to the specified path.

      :param sock: The socket connection to the server.
      :param path: The path to save the received photo.
      """
    photo_len = recv_msg(sock)
    server_photo = sock.recv(int(photo_len))

    with open(path, 'wb') as f:
        f.write(server_photo)
