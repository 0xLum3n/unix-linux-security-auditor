UNIX / LINUX SECURITY MODELS - CASE STUDY PACKAGE
=================================================

CONTENTS
--------
1. Unix_Linux_Security_Models_Case_Study.docx  - editable written report
2. unix_security_auditor.py                     - complete Python program
3. test_unix_security_auditor.py                - 14 automated tests
4. sample_data/                                 - synthetic test files
5. sample_outputs/                              - sample terminal and JSON outputs
6. architecture_diagram.png                    - program architecture
7. requirements.txt                             - dependency note (standard library only)

PLATFORM AND REQUIREMENTS
-------------------------
- Linux, Ubuntu, WSL Ubuntu, macOS, BSD, Solaris or AIX (supported Unix-like systems)
- Python 3.9 or newer
- No third-party Python packages are required
- Windows and other non-Unix platforms are detected immediately; the program prints an
  UNSUPPORTED OPERATING SYSTEM message and exits before importing Unix-only modules
  or starting an inspection. Windows users should run it inside Ubuntu on WSL.
- Optional: getfacl from the 'acl' package to display real POSIX ACL entries
- Run as a normal, non-root user for the most representative current-user access demo; root has elevated discretionary-access privileges.

IMPORTANT SAFETY NOTES
----------------------
- The program does not call chmod, chown, setfacl, or change the permissions of
  inspected files. The inspection and audit functions are read-only.
- The permission simulator calculates a classic mode-bit decision for a
  supplied UID/GID set. It does not impersonate that user or change process IDs.
- The ACL policy simulator uses a synthetic POSIX ACL to demonstrate owner,
  named-user, group-class, mask, and other-entry evaluation. It does not install
  ACL entries on the filesystem.
- The directory audit reports patterns for review. SUID/SGID files can be
  legitimate; never delete or modify them automatically.
- The sample file world_writable_demo.txt is deliberately set to mode 666 so
  the audit can find it. It is a harmless text fixture; do not use mode 666 for
  real confidential files.
- Run audits only on systems and directories you own or are authorised to
  inspect.
- SHA-256 verification detects content changes relative to a saved baseline.
  Keep the baseline in a separate, protected location. If an attacker can
  replace both the file and its baseline, the check can be defeated.

QUICK START
-----------
Open a terminal in the extracted project folder.

1. Check the Python version:
       python3 --version

2. Open the interactive menu:
       python3 unix_security_auditor.py

3. Run the automated tests:
       python3 -m unittest -v test_unix_security_auditor.py
   or:
       python3 unix_security_auditor.py self-test

4. Optional: safely demonstrate the Windows startup guard from a Unix test system:
       python3 -c "import runpy,sys; sys.platform='win32'; runpy.run_path('unix_security_auditor.py', run_name='__main__')"
   It should print UNSUPPORTED OPERATING SYSTEM and exit with status 2.
   A captured example is in sample_outputs/platform_guard_windows.txt.

- Optional: safely demonstrate the Windows startup guard from a Unix test system:
       python3 -c "import runpy,sys; sys.platform='win32'; runpy.run_path('unix_security_auditor.py', run_name='__main__')"
  It should print UNSUPPORTED OPERATING SYSTEM and exit with status 2.
  A captured example is in sample_outputs/platform_guard_windows.txt.

COMMON COMMANDS
---------------
Inspect a real file and query current-process access:
       python3 unix_security_auditor.py inspect sample_data/confidential_exam_records.txt

Simulate classic mode-bit access for a supplied user identity:
       python3 unix_security_auditor.py simulate sample_data/confidential_exam_records.txt --uid 1002 --gids 1002,2000 --operation read

Run the POSIX ACL policy demonstration:
       python3 unix_security_auditor.py acl-demo

Display a real file's ACL (requires getfacl):
       python3 unix_security_auditor.py acl sample_data/confidential_exam_records.txt

Audit the supplied sample directory and export JSON:
       python3 unix_security_auditor.py audit sample_data --json-out sample_outputs/my_audit.json

Create a SHA-256 baseline:
       python3 unix_security_auditor.py baseline sample_data/confidential_exam_records.txt --output sample_outputs/my_baseline.json

Verify the file against the baseline:
       python3 unix_security_auditor.py verify sample_data/confidential_exam_records.txt --baseline sample_outputs/my_baseline.json

OPTIONAL ACL UTILITY
--------------------
On Ubuntu/WSL Ubuntu, install the command-line ACL utilities if needed:
       sudo apt update
       sudo apt install acl

Then inspect an ACL:
       getfacl sample_data/confidential_exam_records.txt

To demonstrate a named-user ACL, use a test file and an existing local user:
       setfacl -m u:<existing_username>:r-- sample_data/confidential_exam_records.txt
       getfacl sample_data/confidential_exam_records.txt

The program only reads and displays real ACL entries; it does not run setfacl.

RESTORE THE SAMPLE FIXTURE MODES (IF ZIP EXTRACTION CHANGED THEM)
------------------------------------------------------------------
       chmod 640 sample_data/confidential_exam_records.txt
       chmod 666 sample_data/world_writable_demo.txt

The second command deliberately makes the demo fixture world-writable so that
option 3 / the audit command can detect it. Do not copy that setting to real data.

HOW TO DEMONSTRATE FILE INTEGRITY SAFELY
----------------------------------------
Use a temporary copy rather than editing the supplied fixture:
       cp sample_data/confidential_exam_records.txt /tmp/integrity-demo.txt
       python3 unix_security_auditor.py baseline /tmp/integrity-demo.txt --output /tmp/integrity-demo.baseline.json
       echo 'test modification' >> /tmp/integrity-demo.txt
       python3 unix_security_auditor.py verify /tmp/integrity-demo.txt --baseline /tmp/integrity-demo.baseline.json

The final verify command should print CHANGE DETECTED and return exit status 1.

WHAT THE TOOL DOES NOT CLAIM
----------------------------
This educational tool is not a replacement for the Linux kernel, a complete
SELinux/AppArmor evaluator, an intrusion-detection system, or a forensic suite.
The mode-bit simulation does not model ACLs, Linux capabilities, mount flags,
MAC policies, directory traversal permissions, or every filesystem-specific
rule. The interactive real-file inspection uses os.access() to ask the OS about
the current process; os.access() is not a safe authorisation gate before open()
because of time-of-check/time-of-use races.

REPORT PERSONALISATION BEFORE SUBMISSION
----------------------------------------
Fill in the student name, university roll number, registration number, college,
faculty name, and academic year on the report cover. The MAKAUT CO-PO-PSO table
uses the publicly available 2022-23 CSE (Cyber Security) syllabus where
Operating System is listed as PCCCS503. Verify the current course code, COs,
and PSO wording with your department if your batch follows a revised scheme.
