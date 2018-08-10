# Cyobstract

**Cyobstract** is a *cyber observables extraction tool* that uses regular expressions on cyber incident reports. It quickly pulls indicators and other cyber information from these reports. It takes free text as input and provides relevant information for incident response (IR) in a structured format as output.

Cyobstract is an IR tool built to support an exploratory inquiry that the CERT Division of the Software Engineering Institute (SEI) performed on a dataset of Department of Homeland Security (DHS) incident reports.

You can feed Cyobstract with the text of your own incident reports—either from an extract of incident reports from a ticketing system or another source (e.g., email, text files, a database, etc.).

Cyobstract applies a list of regular expressions to catch commonly occurring data types and values inside of free text. It also matches on many styles of defanged indicators. (Defanging obfuscates indicators into safer representations so that a user doesn't accidentally click on a malicious URL or inadvertently run malicious code.)

There are two parts to Cyobstract:

1. the **Cyobstract standard package** which can be installed and imported in python then called with `cyobstract.extract` and `cyobstract.trie`

2. the suite of developer tools that can be used to build a custom extraction module

The developer tools are covered in the *Using the Cyobstract Developer Tools* section below.

Important: Cyobstract is a beta project that makes no guarantees regarding stability or functionality.

# Features

There are two main features of Cyobstract: extracting indicators/observables and handling defanged indicators.

## 1. Extracting Indicators/Observables

Cyobstract extracts 24 incident-response-related data types from free text incident reports, such as the commonly used 'incident_description' field:

-	IP addresses—IPv4, IPv4 CIDR, IPv4 range, IPv6, IPv6 CIDR, and IPv6 range
-	hashes—MD5, SHA1, SHA256, and ssdeep
-	Internet and system-related strings—FQDN, URL, user agent strings, email address, filenames, filepath, and registry key
-	Internet infrastructure values—ASN, ASN owner, country, and ISP
-	security analysis values—CVE, malware, and attack type


## 2. Handling Defanged Indicators

Cyber incident responders deal with malicious computer code and, by necessity, they use computers to analyze those samples. It is difficult to simultaneously maintain a safe environment, a high functionality environment, and an environment that allows the rapid communication of results. The IR community adopted a practice called defanging to reduce the chances of accidentally infecting their own (or others’) computers.

Defanging obfuscates indicators into a safer representations so that a user doesn't accidentally click on a malicious URL or inadvertently run malicious code. Defanging means changing data values to deliberately violate Internet protocols. Unfortunately, there is no universal standard for defanging, although there are some common methods. There is even a Python module that can be used to defang certain data types, but not all teams use it.

Typical types of defanged data include IP addresses, fully qualified domain names (FQDNs), email, and file extensions. Some samples of defanging we have observed include the following:

- www dot cert dot org (www.cert.org)
- www[.]cert[.]org
- www[.cert[.org
- www{.}cert{.}org
- incidents at cert dot org (incidents@cert.org)

Our extraction module successfully recognizes and extracts many forms of defanged indicator values.

# Getting Started

To use the prepackaged modules, follow the installation instructions below to install the **Cyobstract standard package**. Details on how to use the modules and what they do are also provided below.

To use the **Cyobstract developer tools**, clone the source repository and use them directly from that location. To use the tools, you must set up a configuration file that specifies your data set of incident reports (or tickets). Configuration details are in the *Configuration* subsection of the *Using the Cyobstract Developer Tools* section below.

Using either the standard package or the developer tools, Cyobstract uses a set of regular expressions to extract 24 information types from the free text in your incident reports. Using the standard package, the extracted fields are returned to your application. Using the developer tools, the extracted fields are stored to disk while being used.

## Installation

Install Python 2.7 or 3.6.

Clone the repository:

```bash
$ git clone https://github.com/cmu-sei/cyobstract.git
```

If you do not have pandas, install it with `pip install pandas`.

Move to the cyobstract directory, run `python setup.py install`.

The dependencies `future`, and `progress` should have installed after running `setup.py`, but if they failed, you can install them using these commands:   

```bash
pip install future   
pip install progress
```  

If you are using the developer tools, there are several dependencies that are detailed in the Using the *Cyobstract Developer Tools* section below.

## Using the Cyobstract.extract module

There are two functions in the `cyobstract.extract` module. Both functions  take an arbitrary string of text as input (for example the 'description' field from a given incident report).

The `extract.extract_observables` function will extract all recognized types of artifacts from the input and return the results in a dictionary (type : values).

```python
from cyobstract import extract

text = # source of text
results = extract.extract_observables(text)
print(results) # for example
```

You can also extract for a particular type of observable using `extract.extract`:

```python
text = # source of text
for observable in extract.extract(text, observable_type):
    print(observable)
```

## Using the cyobstract.trie module

This module contains a function that constructs optimized regular expressions based on a list of tokens:

```python
from cyobstract import trie

tokens = # list of tokens
re_str = trie.re_str_from_tokens(tokens)
```
The details of this module are explored in more detail in Appendix B.


# Using the Cyobstract Developer Tools

The developer tools are useful for developing and refining your own regular expressions and cataloging their results on your incident reports.

## Dependencies

As with the basic installation, use either Python 2.7 or 3.6. Install the following:

    pip install setuptools # at least version 28.05.0   (https://stackoverflow.com/a/40477249)
    pip install pandas
    pip install urllib
    pip install progress

```bash
$ git clone https://code.sei.cmu.edu/bitbucket/projects/USCID/repos/cyobstract/browse
```

## Configuration

Configuration is specified in a YAML file located at `~/.cyobstract`. There are currently only three variables that can be defined. Here is an example template:

```yaml
# repository path (where generated data lives). If undefined,
# it will default to the code repository root. Subdirectories
# are created here (e.g. 'dat', 'log', 'tmp'). If an 'etc'
# directory is here, it will be used, otherwise the 'etc'
# directory from the code repository is used.
repo_path:

# database URI
# e.g. /path/to/sqlite3_file
db_uri: '/database/uri'

# database driver as registered to the smoke.db module
# (custom drivers can be written to match your schema,
# see APPENDIX C)
db_driver: 'db1'
```

## Testing and Regex Development Environment
The regular expressions (and functions) used to extract indicators live in the `cyobstract.extract` module. They consist of manually constructed regular expressions and optimized regexes that are automatically generated from collections of external data in the `./etc` directory. These regular expressions can be further refined and new indicator types and their corresponding regexes can be added to the analysis suite.

For more information on the tool suite that helps with developing new extractions as well as the components of the developer tools, see Appendix A. For details on `cyobstract.trie`, the module used for building optimized regular expressions, see Appendix B.

# Resources

You can read more about Cyobstract in some of our other publications

- [FIRST Conference Presentation: Extracting Indicators from Incident Reports (June 2017)](https://www.first.org/resources/papers/conf2017/Improving-Useful-Data-Extraction-from-Cybersecurity-Incident-Reports.pdf)

- [SEI Blog Post Improving Data Extraction from Cybersecurity Incident Reports (September 2017)](https://insights.sei.cmu.edu/sei_blog/2017/09/improving-data-extraction-from-cybersecurity-incident-reports.html)

# Contact

Please share your stories about using Cyobstract with us!

To learn more about Cyobstract, see the above publications or contact Sam Perl at the CERT Division of the Software Engineering Institute.


# Appendix A: Cyobstract Developer Tools in Detail

Cyobstract developer tools consist of a set of scripts and data. The tools include utilities for building new regexes, exploring the corpus of incident reports, and benchmarking the resulting iterations of extractions as they are refined.

## The Regular Expressions: Where They Come From and Where They Live

The *regular expressions* can be compiled regexes or a callable function; in either case, these expressions should return a list of indicators found throughout the entire block of text provided to it. Regular expressions consist of a combination of manually constructed regexes/functions, automatically generated regexes, and hybrids thereof. For compiled regexes, as opposed to callables, you want only **one** set of capturing parentheses since eventually `.findall()` will be invoked on it.

The manually constructed regular expressions (and functions) reside in `extract/regex.py`. Often, these expressions are built from primitives to improve readability.

The automatically generated regexes reside in `extract/re_auto.py`, which in turn is imported into the main extract module. Since these regular expressions can be very large and complex, they are kept in a separate module to improve the readability of the main module.

Whether manual or automatic, the compiled regex or callable is stored in the `regex.regexes` dictionary under the name of the type of indicator being extracted.

### Auto-Generated Optimized Regular Expressions

Automatically generated regular expressions are derived from lists of tokens that live in data files in the `./etc` directory. Some of these files are manually constructed and some are just raw lists of tokens downloaded from publicly available sources on the Internet.

Sometimes there are also lists of tokens to ignore since we have found some tokens generate too many false positives. The scripts that build the regexes from tokens live in the `./bin` directory.

Below are the current token files, how they are constructed, and the script that builds their respective regexes:

| Generated File                    | Data Method     | Build Script           |
|:------------------------|:-----------|:-----------------|
| country_codes.txt       | downloaded | build_cc_re      |
| country_adjectivals.txt | downloaded | build_cc_re      |
| malware.txt             | manual     | build_malware_re |
| file_exts.txt topic.txt | manual     | build_exts_re    |
| html_entities.txt       | downloaded | build_entity_re  |
| tlds.txt                | downloaded | build_tld_re     |

The scripts take no arguments and print the resulting regular expression to STDOUT. The regexes are grouped using non-capturing parentheses so, when they are eventually compiled, they will need to be embedded in capturing parentheses. Below is an example:

In `extract/re_auto.py`

```python
my_raw_re = """
    <pasted result from script output>
""".strip()
```

Then in `extract/regex.py`

```python
import re
from . import re_auto
...
# this is just an example; you might not want word
# boundaries or you might want different regex options.
# You *do* want capturing parentheses.
my_re = re.compile("\b(%s)\b" % re_auto.my_raw_re, re.X)
```

In all cases, the scripts use the `cyobstract.trie` module to generate the optimized regexes. Details of how that module works can be found in Appendix B.

## Data Exploration

While refining and developing new regular expressions, it can be helpful to explore the collection of incident reports to help you design more precise (or permissive) future iterations. There are several scripts that facilitate this process. Once interesting new ideas or refinements are found, they can be integrated into the standard extraction library.

Note: A few of these scripts use the `multiproccess` module for parallel execution, which is why if you write your own database driver (see APPENDIX C) it is important to track database connections by process ID.

Below is a list of these scripts and descriptions of what each one does. All scripts take `-h` or `--help` to access help that explains the details of their options.

### grep_entry

This script allows the testing of arbitrary regular expressions across specific incident reports, or the entire corpus, typically in random order. Whenever a hit occurs, the incident ID, line number, and incident type are printed to STDOUT along with the line in question. Below is a typical usage for this script:

```bash
grep_entry -r "regex"
```

### extract_entry

This script is similar to `grep_entry`, except it uses the current extraction types that exist in `cyobstract.extract`. It can operate on specific incident reports or the entire corpus. In addition, you can restrict the types of indicators that are used for the search. Below is a typical usage for this script:

```bash
grep_entry -r type_1 type_2
```

### cat_entry

This script simply dumps the given incident reports to STDOUT. Below is a typical usage for this script:

```bash
cat_entry incident_id
```

## Testing Framework—Bulk Query

The `bin/bulk_query` script is the real workhorse of the testing suite. It runs every type of defined extraction across the entire corpus of incident reports. Results are saved and compared to prior runs. These results capture only hits, including true positives and false positives. It does not detect false negatives. When the script finishes running, some statistics are printed to STDOUT that detail what changed between the latest run and the prior run.

The complete results are stored in `dat/extractions/<timestamp>`. For convenience, two soft links are created, `previous` and `current`, that point to their respective timestamped directories.

In each results directory, a text file is created with the type of indicator that it represents. Each of these files is made up of lines with the incident ID and the artifact that was extracted. It is useful to examine the differences between the current run and previous run using a tool such as `diff`.

## Testing Framework-Measured Efficacy

Unlike the bulk query tool, the *smoke* testing suite can specifically detect true positives, false positives, and false negatives. However, to achieve these results, some preparatory work is required. A collection of representative incident reports must be selected and manually parsed for artifacts. Once this is accomplished, the `bin/smoke_test` script runs the extractions on each report, prints some statistics to STDOUT that represents the aggregate difference between the latest run and the prior run, and saves more detailed results in the `dat/out` directory. Three files and three soft links are created:

```bash
    <timestamp>.false_neg.txt
    <timestamp>.false_pos.txt
    <timestamp>.true_pos.txt
    false_neg.txt -> <timestamp>.false_neg.txt
    false_pos.txt -> <timestamp>.false_pos.txt
    true_pos.txt  -> <timestamp>.true_pos.txt
```

### Locating and Preparing an Incident Report for Testing

Representative incident reports must first be selected. These reports can be selected either via manual inspection or through exploratory tools such as `bin/grep_entry`. Once selected, however, the following steps must be taken:

1. Run the command `bin/grab_entry <incident_id>` to save the text of the incident report in `dat/iid/<incident_id>/notes.txt`.

2. (optional but helpful) Run the command `bin/draft_knowns <incident_id>` to create the file `dat/iid/<incident_id>/knowns_draft.txt`. This file is a report of positive matches (both true and false) delineated by line number and the artifact that was extracted. It can be used as a starting point for the next step. After manual parsing, false positives should be deleted and false negatives should be added.

3. Manually parse the incident report and store artifacts that should be extracted in `dat/iid/<incident_id>/knowns.txt`. The conventional formatting is "line_no: artifact".

These three steps should be repeated as often as necessary to get a robust and representative sampling of incident reports. Once these are in place, improvements and regressions while developing the regular expressions can be precisely measured.

# Appendix B: cyobstract.trie (Auto-Generated Optimized Regular Expressions)

The `trie` module is used to construct optimized regular expressions from lists of tokens. It is used by the developer tools, but can also be used as a general purpose tool for building any regular expression.

## Usage

First, print out the generated regular expression:

```python
from cyobstract import trie

tokens = # wherever the list of tokens comes from
re_str = trie.re_str_from_tokens(tokens)
print(re_str)
```

Then pass that result somewhere, such as `my_regex.py`:

```python
   re_str = """
       <pasted regex>
   """.strip()
```

Then in the module where you use it:

```python
import re
import my_regex

# need capturing parenthesis in order to extract anything;
# the word boundary (\b) expressions are just an example
# of something that might surround the larger regex
my_re = re.compile(r"\b(%s)\b" % my_regex.re_str, re.U|re.X)
```
## What It Does

Let's say you have a list of words or phrases, which we'll call tokens. For example, here are four:

```
dog
dingo
cat
doggo
```

The naive way of constructing a regex to match those is something like this:

```
(?:dog|dingo|cat|doggo)
```

The optimizer, on the other hand, constructs a regex based on a prefix map, where shared prefixes are encoded a minimal number of times. So, the above becomes this:

```
(?:cat|(?:d(?:og(?:go)?|ingo)))
```

What this optimization ends up doing is minimizing the amount of backtracking the regex engine needs to do whenever a match fails. Note that `(?:)` denotes a non-capturing group. Also, the "go" at the end of doggo is encoded as optional.

This kind of optimization can be done by hand if you're good with regexes, but where the tool really shines is when your original list comprises dozens or even hundreds of tokens.

Another helpful feature is that regex constructs can be embedded in the tokens. For example, with `quick\s+brown\s+fox` the whitespace expressions `\s+` are treated as a single atom and are preserved in the resulting optimized aggregate expression.


# Appendix C: Writing Customized Database Drivers

Earlier in this file, we describes how a database driver can be specified in the `~/.cyobstract` configuration file (e.g., `db_driver: db1`). Cyobstract ships with one drivers that uses a database schemas: `db1`.

```bash
smoke/db/db_driver_1.py
```

If this schema does not suits your needs, you can add your own. The easiest way to start is to examine the code in this files and modify it accordingly. There are are a three essential things to keep in mind:

1. The driver module must live in the `smoke/db` directory, and the filename must begin with db_driver.

2. The driver modules are responsible for managing their own database connection pool. The database URI can be specified in `~/.cyobstract` but could also be hard coded. Connections should be tracked by process ID.

3. The driver modules must register themselves with the main `smoke.db` module. Below is an example:

```python
import sys
from smoke import db
...
db.register_driver('driver_name', sys.modules[__name__])
```

Once registered, 'driver_name' can be used in `~/.cyobstract` for the db_driver field.
