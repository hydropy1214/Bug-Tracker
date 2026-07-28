{pkgs}: {
  deps = [
    pkgs.git
    pkgs.gitleaks
    pkgs.gobuster
    pkgs.sqlmap
    pkgs.subfinder
    pkgs.ffuf
    pkgs.nuclei
    pkgs.dnsutils
    pkgs.whois
    pkgs.nmap
  ];
}
