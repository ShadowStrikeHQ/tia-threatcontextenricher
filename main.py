import argparse
import hashlib
import logging
import os
import sys
from datetime import datetime

import requests
from dateutil import parser

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)


class VirusTotalAPI:
    """
    A class to interact with the VirusTotal API.
    """

    def __init__(self, api_key):
        """
        Initializes the VirusTotalAPI class.

        Args:
            api_key (str): The VirusTotal API key.
        """
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3/"

    def get_ip_report(self, ip_address):
        """
        Retrieves a report for a given IP address from VirusTotal.

        Args:
            ip_address (str): The IP address to query.

        Returns:
            dict: The JSON response from the VirusTotal API, or None if an error occurs.
        """
        url = self.base_url + f"ip_addresses/{ip_address}"
        headers = {"x-apikey": self.api_key}

        try:
            response = requests.get(url, headers=headers)
            response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
            return response.json()
        except requests.exceptions.RequestException as e:
            logging.error(f"Error querying VirusTotal for IP {ip_address}: {e}")
            return None

    def get_domain_report(self, domain):
        """
        Retrieves a report for a given domain from VirusTotal.

        Args:
            domain (str): The domain to query.

        Returns:
            dict: The JSON response from the VirusTotal API, or None if an error occurs.
        """
        url = self.base_url + f"domains/{domain}"
        headers = {"x-apikey": self.api_key}

        try:
            response = requests.get(url, headers=headers)
            response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
            return response.json()
        except requests.exceptions.RequestException as e:
            logging.error(f"Error querying VirusTotal for domain {domain}: {e}")
            return None

    def get_file_report(self, file_hash):
        """
        Retrieves a report for a given file hash from VirusTotal.

        Args:
            file_hash (str): The file hash (MD5, SHA1, or SHA256) to query.

        Returns:
            dict: The JSON response from the VirusTotal API, or None if an error occurs.
        """
        url = self.base_url + f"files/{file_hash}"
        headers = {"x-apikey": self.api_key}

        try:
            response = requests.get(url, headers=headers)
            response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
            return response.json()
        except requests.exceptions.RequestException as e:
            logging.error(f"Error querying VirusTotal for hash {file_hash}: {e}")
            return None


def is_valid_ip(ip_address):
    """
    Validates if the given string is a valid IPv4 address.  Simple check, could be improved with a more robust regex.

    Args:
        ip_address (str): The string to validate.

    Returns:
        bool: True if the string is a valid IPv4 address, False otherwise.
    """
    parts = ip_address.split(".")
    if len(parts) != 4:
        return False
    try:
        for part in parts:
            if not 0 <= int(part) <= 255:
                return False
        return True
    except ValueError:
        return False


def is_valid_domain(domain):
    """
    Validates if the given string is a valid domain. Simple check, could be improved with a more robust regex.

    Args:
        domain (str): The string to validate.

    Returns:
        bool: True if the string is a valid domain, False otherwise.
    """
    return "." in domain  # Basic check for a dot in the domain


def is_valid_hash(file_hash):
    """
    Validates if the given string is a valid MD5, SHA1, or SHA256 hash.  Uses length checks.

    Args:
        file_hash (str): The string to validate.

    Returns:
        bool: True if the string is a valid hash, False otherwise.
    """
    hash_length = len(file_hash)
    return hash_length == 32 or hash_length == 40 or hash_length == 64


def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.

    Returns:
        argparse.ArgumentParser: The argument parser object.
    """
    parser = argparse.ArgumentParser(
        description="Enriches an IP address, domain, or hash with context from VirusTotal."
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "-i", "--ip", help="IP address to lookup"
    )  # Changed to -i for brevity and common usage
    group.add_argument(
        "-d", "--domain", help="Domain to lookup"
    )  # Changed to -d for brevity
    group.add_argument(
        "-f", "--file", help="File hash (MD5, SHA1, SHA256) to lookup"
    )  # Changed to -f for brevity
    parser.add_argument(
        "-k",
        "--apikey",
        help="VirusTotal API key. Can also be set via environment variable VIRUSTOTAL_API_KEY.",
    )  # Added -k for brevity and to allow setting API key from env
    parser.add_argument(
        "-o", "--output", help="Output file to save the report (optional)"
    )  # Added -o for outputting to file

    return parser


def analyze_ip(vt_api, ip_address, output_file=None):
    """
    Analyzes an IP address using the VirusTotal API and prints a summary.

    Args:
        vt_api (VirusTotalAPI): The VirusTotal API object.
        ip_address (str): The IP address to analyze.
        output_file (str, optional): The file path to write the report to. Defaults to None.
    """

    report = vt_api.get_ip_report(ip_address)

    if report:
        attributes = report.get("data", {}).get("attributes", {})
        last_analysis_stats = attributes.get("last_analysis_stats", {})
        total_votes = attributes.get("total_votes", {})
        reputation = attributes.get("reputation", 0)

        output = f"IP Address: {ip_address}\n"
        output += f"  Reputation: {reputation}\n"
        output += f"  Harmless: {last_analysis_stats.get('harmless', 0)}\n"
        output += f"  Malicious: {last_analysis_stats.get('malicious', 0)}\n"
        output += f"  Suspicious: {last_analysis_stats.get('suspicious', 0)}\n"
        output += f"  Undetected: {last_analysis_stats.get('undetected', 0)}\n"
        output += f"  Total Votes (Harmless): {total_votes.get('harmless', 0)}\n"
        output += f"  Total Votes (Malicious): {total_votes.get('malicious', 0)}\n"

        if "last_analysis_results" in attributes:
            output += "\n  Analysis Results (First 5):\n"
            count = 0
            for engine, result in list(
                attributes["last_analysis_results"].items()
            )[:5]:  # Limit to first 5 results
                output += f"    {engine}: {result['category']} ({result['result']})\n"
                count += 1
        else:
            output += "\n  No analysis results available.\n"

        print(output)

        if output_file:
            try:
                with open(output_file, "w") as f:
                    f.write(output)
                logging.info(f"Report saved to {output_file}")
            except Exception as e:
                logging.error(f"Error writing to output file {output_file}: {e}")

    else:
        print(f"No VirusTotal report found for IP address: {ip_address}")


def analyze_domain(vt_api, domain, output_file=None):
    """
    Analyzes a domain using the VirusTotal API and prints a summary.

    Args:
        vt_api (VirusTotalAPI): The VirusTotal API object.
        domain (str): The domain to analyze.
        output_file (str, optional): The file path to write the report to. Defaults to None.
    """

    report = vt_api.get_domain_report(domain)

    if report:
        attributes = report.get("data", {}).get("attributes", {})
        last_analysis_stats = attributes.get("last_analysis_stats", {})
        reputation = attributes.get("reputation", 0)

        output = f"Domain: {domain}\n"
        output += f"  Reputation: {reputation}\n"
        output += f"  Harmless: {last_analysis_stats.get('harmless', 0)}\n"
        output += f"  Malicious: {last_analysis_stats.get('malicious', 0)}\n"
        output += f"  Suspicious: {last_analysis_stats.get('suspicious', 0)}\n"
        output += f"  Undetected: {last_analysis_stats.get('undetected', 0)}\n"

        if "last_analysis_results" in attributes:
            output += "\n  Analysis Results (First 5):\n"
            count = 0
            for engine, result in list(
                attributes["last_analysis_results"].items()
            )[:5]:  # Limit to first 5 results
                output += f"    {engine}: {result['category']} ({result['result']})\n"
                count += 1
        else:
            output += "\n  No analysis results available.\n"

        print(output)

        if output_file:
            try:
                with open(output_file, "w") as f:
                    f.write(output)
                logging.info(f"Report saved to {output_file}")
            except Exception as e:
                logging.error(f"Error writing to output file {output_file}: {e}")

    else:
        print(f"No VirusTotal report found for domain: {domain}")


def analyze_file(vt_api, file_hash, output_file=None):
    """
    Analyzes a file hash using the VirusTotal API and prints a summary.

    Args:
        vt_api (VirusTotalAPI): The VirusTotal API object.
        file_hash (str): The file hash to analyze.
        output_file (str, optional): The file path to write the report to. Defaults to None.
    """

    report = vt_api.get_file_report(file_hash)

    if report:
        attributes = report.get("data", {}).get("attributes", {})
        last_analysis_stats = attributes.get("last_analysis_stats", {})
        reputation = attributes.get("reputation", 0)
        names = attributes.get("names", [])
        type_description = attributes.get("type_description", "N/A")
        size = attributes.get("size", "N/A")

        output = f"File Hash: {file_hash}\n"
        output += f"  Names: {', '.join(names) if names else 'N/A'}\n"
        output += f"  Type Description: {type_description}\n"
        output += f"  Size: {size} bytes\n"
        output += f"  Reputation: {reputation}\n"
        output += f"  Harmless: {last_analysis_stats.get('harmless', 0)}\n"
        output += f"  Malicious: {last_analysis_stats.get('malicious', 0)}\n"
        output += f"  Suspicious: {last_analysis_stats.get('suspicious', 0)}\n"
        output += f"  Undetected: {last_analysis_stats.get('undetected', 0)}\n"

        if "last_analysis_results" in attributes:
            output += "\n  Analysis Results (First 5):\n"
            count = 0
            for engine, result in list(
                attributes["last_analysis_results"].items()
            )[:5]:  # Limit to first 5 results
                output += f"    {engine}: {result['category']} ({result['result']})\n"
                count += 1
        else:
            output += "\n  No analysis results available.\n"

        print(output)

        if output_file:
            try:
                with open(output_file, "w") as f:
                    f.write(output)
                logging.info(f"Report saved to {output_file}")
            except Exception as e:
                logging.error(f"Error writing to output file {output_file}: {e}")

    else:
        print(f"No VirusTotal report found for hash: {file_hash}")


def main():
    """
    Main function to drive the threat context enrichment process.
    """

    parser = setup_argparse()
    args = parser.parse_args()

    # Get API key from command line or environment variable
    api_key = args.apikey or os.environ.get("VIRUSTOTAL_API_KEY")
    if not api_key:
        logging.error(
            "VirusTotal API key is required. Provide it via --apikey or VIRUSTOTAL_API_KEY environment variable."
        )
        sys.exit(1)

    vt_api = VirusTotalAPI(api_key)

    if args.ip:
        if is_valid_ip(args.ip):
            analyze_ip(vt_api, args.ip, args.output)
        else:
            logging.error("Invalid IP address.")
            sys.exit(1)
    elif args.domain:
        if is_valid_domain(args.domain):
            analyze_domain(vt_api, args.domain, args.output)
        else:
            logging.error("Invalid domain.")
            sys.exit(1)
    elif args.file:
        if is_valid_hash(args.file):
            analyze_file(vt_api, args.file, args.output)
        else:
            logging.error("Invalid file hash.")
            sys.exit(1)


if __name__ == "__main__":
    main()