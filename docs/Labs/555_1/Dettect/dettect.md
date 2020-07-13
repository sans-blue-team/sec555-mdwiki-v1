Exercise 1.1 - Utilizing DeTTECT to Visualize Visibility and Detection Capabilities
==========================================================

Objectives
==========

- Review the Functionality of DeTTECT
- Add Data Sources to DeTTECT
- Visualize Data Sources to the MITRE Framework 

Exercise Preparation
==========

Log into the Sec-530 VM

- Username: student

- Password: Security530

![](./media/image1.png)  

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
### Visualize Data Sources to the MITRE Framework 

We have explored the threat to Hacme Cats as a retail business. Now it is time to explore how much coverage Hacme Cats has against the techniques we have identified. To do that, we will use the open-source framework DeTTECT. To run DeTTECT inside a docker container and open up a shell on it, run:

```bash
$ docker run --rm -p 8080:8080 -v /labs/threatmodeling/output:/opt/DeTTECT/output -v /labs/threatmodeling/input:/opt/DeTTECT/input --name dettect -it rabobankcdc/dettect:v1.3 /bin/bash
```

<button onclick="copyToClipboard('docker run --rm -p 8080:8080 -v /labs/threatmodeling/output:/opt/DeTTECT/output -v /labs/threatmodeling/input:/opt/DeTTECT/input --name dettect -it rabobankcdc/dettect:v1.3 /bin/bash')" style="background-image: url(/clipboard.svg); background-repeat: no-repat; height: 40px; width: 40px;"> 
</button>

<p> </p>

**Note:** This command will run the DeTTECT image inside a docker container, and will map the **/labs/threatmodeling/input** and **/labs/threatmodeling/output** on your VM to **/opt/DeTTECT/input** and **/opt/DeTTECT/output** inside the container, respectively. It will also map TCP port 8080 on your VM to port 8080 on the container. You will learn more about docker containers throughout this class. 

To access the interactive editor in your VM, execute this command inside the docker container:

```bash
$ python dettect.py editor &
```

<button onclick="copyToClipboard('python dettect.py editor &')" style="background-image: url(/clipboard.svg); background-repeat: no-repat; height: 40px; width: 40px;"> 
</button>

<p> </p>

You may need to hit Enter at least once to get back to the bash prompt. You can now open the Editor on your VM on http://localhost:8080/dettect-editor. Make sure the browser is maximized so you can see the left side menu:

![](./media/image16.png) 
