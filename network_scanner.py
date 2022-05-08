from typing import Protocol, List, Optional
from socket import gethostbyname, socket, AF_INET, SOCK_STREAM, gaierror, error as sock_error
import os
import sys

IP_ADDERESSES_QUEUE = ['216.58.211.196']


class PortResult(Protocol):
    port: int
    is_open: bool
    is_http: Optional[bool]

    @staticmethod
    def update(i_port = 0, i_is_open = False, i_is_http = False):
        global port, is_open, is_http
        port = i_port
        is_open = i_is_open
        is_http = i_is_http
        


class ScanResult(Protocol):
    id: int
    is_alive: bool
    ports: List[PortResult]

    @classmethod
    def update_scan(cls, i_id = 0, i_is_alive = False, i_port = None):
        ScanResult.id = i_id
        ScanResult.is_alive = i_is_alive
        ScanResult.ports.append(i_port)
    

class ScanRequest(Protocol):
    """
    Summary: ScanRequest class -> will represent the IP Scan Request and contains the following data.
        id: int
        ipv4: str
        ports: List[int]
    """
    id = 0
    ipv4 = ''
    ports = []

    @classmethod
    def get(cls):
        ScanResult.ports = []
        is_alive = False
        if ScanRequest.ipv4: 
            remoteServerIP  = gethostbyname(ScanRequest.ipv4)
            res = os.system(f'ping -c 1 -W 3000 -a {ScanRequest.ipv4}')
            if res != 0:
                print("Port is still alive")
            else:
                for port in ScanRequest.ports:
                    try:
                        sock = socket(AF_INET, SOCK_STREAM)
                        sock.settimeout(10)
                        result =  sock.connect((remoteServerIP, port))
                        ScanRequest.id = sock.getsockname()[1]
                        print(ScanRequest.id)
                        if result:
                            print("Port {}: 	 Open".format(port))
                            ScanRequest.ports.remove(port)
                        else:
                            print("Port {} is reachable ... -> Closed".format(port))
                            is_alive = True
                            is_http = True if port == 80 else False
                            PortResult.update(i_port=port, i_is_open=True, i_is_http=is_http)

                        sock.close()
                    except TimeoutError:
                        print("Hostname is unrechable with Port {}, Connection timed out.".format(port))
                        PortResult.is_open = False
                    except KeyboardInterrupt:
                        print("You pressed Ctrl+C")
                        sys.exit()

                    except gaierror:
                        print('Hostname could not be resolved.')
                        is_alive = False
                        continue

                    except sock_error:
                        print("Couldn't connect to server with Port {}, Connection timed out.".format(port))
                        PortResult.is_open = False
                        continue

                    finally:
                        PortResult.port = port

                    ScanResult.update_scan(i_id=id, i_is_alive=is_alive, i_port=PortResult)


if __name__ == '__main__':
    ScanRequest.ports = [23, 80, 443, 512]
    while IP_ADDERESSES_QUEUE:
        ip = IP_ADDERESSES_QUEUE.pop()
        ScanRequest.ipv4 = ip
        ScanRequest.get()

    print(ScanResult)
    print(ScanResult.id)
    print(ScanResult.is_alive)
    print(ScanResult.ports)
