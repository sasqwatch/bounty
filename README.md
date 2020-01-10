# Bounty 

The quicker credential picker upper.

Currently supports SSH and SNMP credential collection.

## Usage

1. Build and/or install a binary


```
$ GOOS=win32 GOARCH=amd64 go build -o bounty.exe
```

```
$ go install -v github.com/hdm/bounty
```

2. Run the binary and collect credentials
```
C:\> bounty.exe

time="2020-01-09T22:50:09-04:00" level=info community=public port=161 proto=snmp src="192.168.88.1:50454" version=2c

time="2020-01-09T22:50:09-04:00" level=info community=private port=161 proto=snmp src="192.168.88.1:50454" version=2c

time="2020-01-09T22:44:31-04:00" level=info method=password password=SuperS3cret^@@ proto=ssh src="127.0.0.1:62428" username=root version=SSH-2.0-OpenSSH_for_Windows_7.7

time="2020-01-09T22:44:29-04:00" level=info method=pubkey proto=ssh pubkey="ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBAab7o6TbLRk4m4OgM52+rv8HEDDj6qceyOckiX+W36iNWHOoXthI0tcZcg7A3bAj4XVJFaD+rvYuJ2u9+KeyHw=" pubkey-sha256="SHA256:Br+7Zi1y9Zr72Ps5v3oy3JMol+yPr4ed07LOUs0v7RE" src="127.0.0.1:62428" username=svc-account-a version=SSH-2.0-OpenSSH_for_Windows_7.7

```