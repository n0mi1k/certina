# certina
certina is an information gathering tool for red teamers to discover subdomains from web certificates.

## Options
```console
USAGE:
  python3 certina.py [flags]

FLAGS:
   -h, --help        Show help message and exit
   -d, --domain      Endpoint to scan separate by commas for multiple domains
   -s, --socket      Enable SSL connection with raw socket (Default: False)
   -i, --input       Input file containing lines of domains
   -o, --output      Output filename to save results
   -c, --certonly    Show only certificate info without further enumeration (Default: False)
   -r, --request     Follow up with GET request to check web-alive (Default: False)
```

## Example Usage
- Full enumeration on SAN/crt.sh and check if web-alive  
`python3 certina.py -d example.com -r`

- Only grab certificate info and SAN extension domains  
`python3 certina.py -d example.com -c`

- Running on multiple domains at once  
`python3 certina.py -d "example.com, example2.com"` or   
`python3 certina.py -i input.txt`

- Only grab certificate info and SAN extension domains  
`python3 certina.py -d example.com -c`

- Running with raw socket mode without SSL library  
`python3 certina.py -d example.com -s`

- Output results to file      
`python3 certina.py -d example.com -o output.txt`

## Disclaimer
This tool is for educational and testing purposes only. Do not use it to exploit the vulnerability on any system that you do not own or have permission to test. The authors of this script are not responsible for any misuse or damage caused by its use.
