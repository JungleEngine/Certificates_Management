# Certificates_Management
simulation of key management and distribution.

### Dependencies
1.python3<br/><br/>
2.flask:`pip3 install Flask`

### Running
1.run the Certificate Authority server: `python3.6 CA.py` runs on port 5000 <br>
2.run first client `python3.6 client.py -p 3000 -op 4000`<br>
2. run second client `python3.6 client.py -p 4000 -op 3000 `<br>
## Flags:
`-p`: client's port <br>
`-op`: other client's port <br>
