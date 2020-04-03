DNSProbe is a community tool built on top of `[retryabledns](https://github.com/projectdiscovery/retryabledns)` that allows you to perform multiple dns queries of your choice with a list of user supplied resolvers

# Usage

```bash
dnsprobe -h
```
This will display help for the tool. Here are all the switches it supports.

| Flag           | Description                                                        | Example                   |
|----------------|--------------------------------------------------------------------|---------------------------|
| -c             | Max dns retries (default 1)                                        | dnsprobe -c 5             |
| -l             | List of dns domains                                                | dnsprobe -l domains.txt   |
| -r             | Request Type A, NS, CNAME, SOA, PTR, MX, TXT, AAAA (default "A")   | dnsprobe -r A             |
| -s             | List of resolvers                                                  | dnsprobe -r resolvers.txt |
| -t             | Number of concurrent requests to make (default 250)                | dnsprobe -t 500           |
| -v             | Output full responses                                              | dnsprobe -v               |

# Installation Instructions
### From Source

DNSProbe requires go1.13+ to install successfully. Run the following command to get the repo - 

```bash
> go get -u -v github.com/projectdiscovery/dnsprobe/cmd
```

In order to update the tool, you can use -u flag with `go get` command.

### Resolving Domains

To query a list of domains, you can pass the list via stdin.

```bash
> cat domains.txt | dnsprobe
```

This will run the tool against domains in `domains.txt` and returns the results. The tool uses the resolvers specified with -s option to perform the queries or default system resolvers.

# License

DNSProbe is made with 🖤 by the [projectdiscovery](https://projectdiscovery.io) team.
