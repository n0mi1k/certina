import ssl
import datetime
import argparse
import warnings
import requests
import re
import socket
import base64
from cryptography import x509

warnings.filterwarnings("ignore")

RED = "\033[91m"
YELLOW = "\033[93m"
LIGHT_GREEN = "\033[92;1m"
LIGHT_BLUE = "\033[96m"
RESET = "\033[0m"

USERAGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

"""
Grabs certificate from endpoint with SSL library
NOTE: Some endpoints may return error. Check domain or add www.
"""
def grabCertificate(endpoint, filePointer):
    try:
        certificate: bytes = ssl.get_server_certificate((endpoint, 443)).encode('utf-8')
        x509Cert = x509.load_pem_x509_certificate(certificate)
    except Exception as e:
        printWriter(f"Failed {endpoint}: {e}", filePointer)
        exit()
    
    printWriter(f"<<<<-----Analysing {endpoint} Certificate----->>>>", filePointer, YELLOW)
    return x509Cert


"""
Alternative method using raw sockets to grab certificate
WARNING: Might be dangerous with use of self created sockets, use with caution
"""
def grabWithSocket(endpoint, filePointer):
    printWriter(f"<<<<-----Analysing {endpoint} Certificate----->>>>", filePointer, YELLOW)
    printWriter("[!] WARNING: Grabbing certificate with socket", filePointer, YELLOW)
    dst = (endpoint, 443)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5) # Set 5s timeout for unreachable hosts

    try:
        s.connect(dst)
    except TimeoutError:
        return None

    # Upgrade the socket to SSL (Try, Except to detect non SSL sites and handshake errors)
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        s = ctx.wrap_socket(s, server_hostname=dst[0])
    except:
        return None

    cert_bin = s.getpeercert(True)
    certb64 = base64.b64encode(cert_bin).decode('ascii')

    s.shutdown(socket.SHUT_RDWR)
    s.close()

    # Convert DER to PEM and loading it like grabCertificate()
    pem_cert = "-----BEGIN CERTIFICATE-----\n"
    pem_cert += certb64
    pem_cert += "\n-----END CERTIFICATE-----\n"

    certificate_bytes = pem_cert.encode('utf-8')
    x509Cert = x509.load_pem_x509_certificate(certificate_bytes)

    return x509Cert


"""
Parses certificate information of x509 certificate
"""
def getCertificateInfo(x509Cert, filePointer):
    # Obtaining basic cert information
    try:
        commonName = x509Cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value
    except:
        printWriter("[!] Failed to get cert info, please check domain or add www.", filePointer, RED)
        exit()

    # Multi try blocks to catch empty values
    try:
        organizationName = x509Cert.subject.get_attributes_for_oid(x509.oid.NameOID.ORGANIZATION_NAME)[0].value
    except IndexError:
        organizationName = "<Not Part Of Certificate>"

    try:    
        subjectSerialNumber = x509Cert.subject.get_attributes_for_oid(x509.oid.NameOID.SERIAL_NUMBER)[0].value
    except IndexError:
        subjectSerialNumber = "<Not Part Of Certificate>"
    
    try:
        countryName = x509Cert.subject.get_attributes_for_oid(x509.oid.NameOID.COUNTRY_NAME)[0].value
    except IndexError:
        countryName = "<Not Part Of Certificate>"

    try:
        localityName = x509Cert.subject.get_attributes_for_oid(x509.oid.NameOID.LOCALITY_NAME)[0].value
    except IndexError:
        localityName = "<Not Part Of Certificate>"
    
    try:
        stateProvince = x509Cert.subject.get_attributes_for_oid(x509.oid.NameOID.STATE_OR_PROVINCE_NAME)[0].value
    except IndexError:
        stateProvince = "<Not Part Of Certificate>"

    # Add on accordingly if more fields are needed
        
    ## Check validity of certificate
    validityStart = x509Cert.not_valid_before
    validityEnd = x509Cert.not_valid_after

    validity = True
    today = datetime.datetime.utcnow()

    if not validityStart < today < validityEnd:
        validity = False
    
    # Obtaining SAN domains from the certificate extension section
    sanExtension = x509Cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    sanDomains = sanExtension.value.get_values_for_type(x509.DNSName)

    # Obtaining issuer information
    issuer = x509Cert.issuer
    country = issuer.get_attributes_for_oid(x509.oid.NameOID.COUNTRY_NAME)[0].value
    organization = issuer.get_attributes_for_oid(x509.oid.NameOID.ORGANIZATION_NAME)[0].value
    issuerCN = issuer.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value

    # I only grabbed a few fields here, for intel use, if you need other fields, just add on
    certInfo = {
        "CommonName" : commonName,
        "Organization" : organizationName,
        "SubjectSerial" : subjectSerialNumber,
        "Country" : countryName,
        "Locality" : localityName,
        "stateProvince" : stateProvince,
        "Validity" : validity,
        "Issuer" : f"CN={issuerCN}, O={organization}, C={country}",
        "SAN" : sanDomains
    }

    return certInfo


"""
Returns SAN domains extracted from x509 cert
"""
def extractSAN(endpoint, sanList, requestFlag, filePointer):
    uniqEndpoints = []

    for domain in sanList:
        validDomain, cleanedDomain = cleanDomain(endpoint, domain)
        if validDomain:
            uniqEndpoints.append(cleanedDomain)
    
    sanUniq = set(uniqEndpoints)
    printWriter(f"[+] {len(sanUniq)} Domains retrieved from SAN", filePointer, LIGHT_BLUE)

    for d in sanUniq:
        if requestFlag:
            status, title, urlScheme = reqDomain(d)
            if status:
                if title:
                    printWriter(f"{d} [{urlScheme}] [{status}] [{title}]", filePointer)
                else:
                    printWriter(f"{d} [{urlScheme}] [{status}]", filePointer)
            else:
                printWriter(f"{d}", filePointer)
        else:
            printWriter(d, filePointer)
    return sanUniq


"""
Returns domains from certificate transparency databases (crt.sh)
"""
def crtshQuery(domain, requestFlag, filePointer):
    crtResult = True
    crtList = []

    # Warning, sometimes crt.sh will throw a "Flush request" error, this is their server issue and can't be fixed
    try:
        r = requests.get(f"https://crt.sh/?q={domain.strip()}&output=json", headers={'User-Agent':USERAGENT})
        jsonResult = r.json()
    except Exception as e:
        crtResult = False
        printWriter(f"-----Error or no results from crt.sh-----", filePointer, RED)
        return crtList

    if r.status_code != 200:
        printWriter(f"-----Error resp from crt.sh [status: {r.status_code}]-----", filePointer, RED)
        return crtList
    
    if crtResult:
        for result in jsonResult:
            cName = result["common_name"]

            if cName is not None:
                inScopeDomain, cleanedDomain = cleanDomain(domain, cName)
                if inScopeDomain:
                    crtList.append(cleanedDomain)

            matchingIdentities = result["name_value"].strip().split("\n")

            if len(matchingIdentities) > 0:
                for singleDomain in matchingIdentities:
                    inScopeDomain, cleanedDomain = cleanDomain(domain, singleDomain)
                    if inScopeDomain:
                        crtList.append(cleanedDomain)

    crtUniq = set(crtList)
    printWriter(f"[+] {len(crtUniq)} Domains retrieved from crt.sh", filePointer, LIGHT_BLUE)

    for d in crtUniq:
        if requestFlag:
            status, title, urlScheme = reqDomain(d)
            if status:
                if title:
                    printWriter(f"{d} [{urlScheme}] [{status}] [{title}]", filePointer)
                else:
                    printWriter(f"{d} [{urlScheme}] [{status}]", filePointer)
            else:
                printWriter(f"{d}", filePointer)
        else:
            printWriter(d, filePointer)

    return crtUniq


"""
Query Censys API for intel
"""
def censysQuery():
    print("Future works")


"""
Sets validity of domain after checking scope, validity and cleaning it
"""
def cleanDomain(domain, testDomain):
    validDomain = False
    if '*.' in testDomain:
        testDomain = testDomain.replace('*.', '')

    if f".{domain}" in testDomain:
        validDomain = True

    if re.search(r'[^a-zA-Z0-9-.]', testDomain):
        validDomain = False

    return validDomain, testDomain


"""
Requests the title page to check
"""
def reqDomain(domain, timeout=2, urlScheme="https"):
    title = None
    failedRequest = False
    try:
        r = requests.get('https://' + domain.strip(), timeout=timeout, allow_redirects=True, verify=True, headers={'User-Agent':USERAGENT})
    except TimeoutError:
        failedRequest = True
    except:
        failedRequest = True
    
    if failedRequest:
        try:
            r = requests.get('http://' + domain.strip(), timeout=timeout, allow_redirects=True, headers={'User-Agent':USERAGENT})
            urlScheme="http"
        except TimeoutError:
            return None, None, None
        except:
            return None, None, None
    
    searchTitle = re.search(r'(?<=<title>).*(?=</title>)', r.text, re.IGNORECASE)
    if searchTitle is not None:
        title = searchTitle.group(0)

    return str(r.status_code), title, urlScheme


"""
Prints and write to file if --output is set
"""
def printWriter(stdout, filePointer=None, color=None):
    if color:
        print(f"{color}{stdout}{RESET}")
    else:
        print(stdout)

    if filePointer is not None:
        filePointer.write(stdout + "\n")


def printBannerArt():
    art = rf"""{LIGHT_BLUE}  ____________  ___________  _____ 
 / ___/ __/ _ \/_  __/  _/ |/ / _ |
/ /__/ _// , _/ / / _/ //    / __ |n0mi1k
\___/___/_/|_| /_/ /___/_/|_/_/ |_| v1.0{RESET}
    """
    print(art)


def main():
    printBannerArt()
    parser = argparse.ArgumentParser(prog='certinfo.py', 
                                    description='A certificate enumeration and information gathering tool.',
                                    usage='%(prog)s -e ENDPOINTS')

    parser.add_argument("-d", "--domain", help="Endpoints to scan separated by commas", required=False)
    parser.add_argument("-s", "--socket", help="Use self-defined socket to grab certificate", default=False, action=argparse.BooleanOptionalAction)
    parser.add_argument("-i", "--input", help="Input file containing domains to analyse", required=False)
    parser.add_argument("-o", "--output", help="File to output the results", required=False)
    parser.add_argument("-c", "--certonly", help="Show only certificate info without further enumeration", default=False, action=argparse.BooleanOptionalAction)
    parser.add_argument("-r", "--request", help="Follow up with GET request", default=False, action=argparse.BooleanOptionalAction)

    args = parser.parse_args()
    inputFile = args.input
    outputFile = args.output
    requestFlag = args.request
    certOnlyFlag = args.certonly
    domainString = args.domain

    filePointer = None

    if outputFile:
        filePointer = open(outputFile, 'w')

    if domainString:
        endpoints = domainString.replace(" ", "").split(",")

    if inputFile:
        endpoints = []
        try:
            with open(inputFile, 'r') as inFile:
                for domains in inFile:
                    endpoints.append(domains.strip())
        except FileNotFoundError:
            print(f"{RED}[!] Error: Input file does not exist{RESET}")
            exit()

    if domainString is None and inputFile is None:
        print(f"{RED}[!] Error: No endpoints specified with -e or -i{RESET}")
        exit()
                 
    for endpoint in endpoints:
        if 'http://' in endpoint:
            print(f"{RED}[!] Scheme http:// included, stripping away...{RESET}") 
            endpoint = endpoint.lstrip('http://')
        elif 'https://' in endpoint:
            print(f"{RED}[!] Scheme http:// included, stripping away...{RESET}")
            endpoint = endpoint.lstrip('https://')

        if not args.socket:
            parsedCert = grabCertificate(endpoint, filePointer)
        else:
            parsedCert = grabWithSocket(endpoint, filePointer)

        certInfo = getCertificateInfo(parsedCert, filePointer)

        for fieldKey in certInfo:
            if fieldKey != "SAN":
                printWriter(f"-> {fieldKey}: {certInfo[fieldKey]}", filePointer)

        if certOnlyFlag:
            printWriter(f"-> SAN DNS Name(s): {certInfo['SAN']}", filePointer)
            continue

        sanUniq = extractSAN(endpoint, certInfo["SAN"], requestFlag, filePointer) # Use this set if you need to implement on other tools
        crtUniq = crtshQuery(endpoint, requestFlag, filePointer) # Use this set if you need to implement on other tools

        if len(sanUniq) != 0 and len(crtUniq) != 0:
            combinedDomains = (sanUniq).union(crtUniq)
            printWriter(f"-----Total {endpoint} domains discovered: {len(combinedDomains)}-----", filePointer, LIGHT_GREEN)
        elif len(sanUniq) != 0:
            printWriter(f"-----Total {endpoint} domains discovered: {len(sanUniq)}-----", filePointer, LIGHT_GREEN)
        elif len(crtUniq) != 0:
            printWriter(f"-----Total {endpoint} domains discovered: {len(crtUniq)}-----", filePointer, LIGHT_GREEN)
        else:
            printWriter(f"-----No {endpoint} domains discovered-----", filePointer, RED)

    if outputFile:
        filePointer.close()


if __name__ == '__main__':
    main()