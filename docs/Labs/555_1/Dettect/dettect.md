Exercise 1.1 - Utilizing DeTTECT to Visualize Visibility and Detection Capabilities
==========================================================

Objectives
==========

- Review the Functionality of DeTTECT
- Add Data Sources to DeTTECT
- Visualize Data Sources to the MITRE Framework 

Exercise Preparation
==========

Log into the Sec-555 VM

- Username: student

- Password: sec555

We will be looking at a company called LabMeINC. Our objective is to review their current data sources and determine if we have the appropriate visibility and detection capabilities for their organization. LabMeINC is like most organizations and has the following data sources currently being ingested into their Security Incident and Events Management(SIEM) system. 
* Windows Logs
* Endpoint Security Logs
* Linux Logs
* Network Device Logs 

To accomplish this review we will be utilizing a tool called DeTTECT which will allow us to map out the data sources that LabMeINC is collecting and determine what visibility they have. Let start by reviewing the functionality that DeTTECT provides. 

### Review the Functionality of DeTTECT

DeTT&CT aims to assist blue teams using ATT&CK to score and compare data log source quality, visibility coverage, detection coverage and threat actor behaviours. All of which can help, in different ways, to get more resilient against attacks targeting your organisation. The DeTT&CT framework consists of a Python tool, YAML administration files, the DeTT&CT Editor and scoring tables for the different aspects.

DeTT&CT provides the following functionality:

* Administrate and score the quality of your data sources.
* Get insight on the visibility you have on for example endpoints.
* Map your detection coverage.
* Map threat actor behaviours.
* Compare visibility, detections and threat actor behaviours to uncover possible improvements in detection and visibility. This can help you to prioritise your blue teaming efforts.

### Add Data Sources to DeTTECT

Now that we know a little more about DeTTECT lets launch it and begin to map our the data sources from LabMeINC.

To begin click on the **terminal icon** at the top of the Student VM.

![](./media/image1.png)

**Copy** and **Paste** the following command in the terminal window and **Press Enter**

```bash
$ docker run --rm -p 8080:8080 -v /labs/threatmodeling/output:/opt/DeTTECT/output -v /labs/threatmodeling/input:/opt/DeTTECT/input --name dettect -it rabobankcdc/dettect:v1.3 /bin/bash
```
!!! note
    This command will run the DeTTECT image inside a docker container, and will map the **/labs/threatmodeling/input** and **/labs/threatmodeling/output** on your VM to **/opt/DeTTECT/input** and **/opt/DeTTECT/output** inside the container, respectively. It will also map TCP port 8080 on your VM to port 8080 on the container.
    
**Copy** and **Paste** the following command in the terminal window and **Press Enter**

```bash
$ python dettect.py editor &
```

**Open** Firefox on your Student VM and browse to the following **URL**

```bash
http://localhost:8080/dettect-editor
```

This will take you to the web interface for DeTTECT that we locally are running on your VM. You should see the following screen. 

![](./media/dettect_home.png)

We will begin by clicking on **Data Sources**







### Visualize Data Sources to the MITRE Framework 


