Exercise 1.1 - Practical Threat Modeling with MITRE ATT&CK
==========================================================

Objectives
==========

- Learn how to prioritize your defensive strategy based on relevant threats

- Understand your visibility and detection coverage based on MITRE ATT&CK

- Measuring the availability and quality of data sources to determine what attacker techniques can be detected

- Simulate specific threat scenarios using DeTTECT & MITRE ATT&CK Navigator

- Leverage analytics, threat intelligence reports and heatmaps to conduct a visibility and detection gap analysis

Exercise Preparation
==========

Log into the Sec-530 VM

- Username: student

- Password: Security530

![](./media/image1.png)  

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
