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
docker run --rm -p 8080:8080 -v /labs/threatmodeling/output:/opt/DeTTECT/output -v /labs/threatmodeling/input:/opt/DeTTECT/input --name dettect -it rabobankcdc/dettect:v1.3 /bin/bash
```
!!! note
    This command will run the DeTTECT image inside a docker container, and will map the **/labs/threatmodeling/input** and **/labs/threatmodeling/output** on your VM to **/opt/DeTTECT/input** and **/opt/DeTTECT/output** inside the container, respectively. It will also map TCP port 8080 on your VM to port 8080 on the container.
    
**Copy** and **Paste** the following command in the terminal window and **Press Enter**

```bash
python dettect.py editor &
```

**Open** Firefox on your Student VM and browse to the following **URL**

```bash
http://localhost:8080/dettect-editor
```

This will take you to the web interface for DeTTECT that we locally are running on your VM. You should see the following screen. We will begin by clicking on **Data Sources**

![](./media/dettect_home.png)

Next, click **New file**

![](./media/dettect_new_file.png)

#### Windows

Then click **Add data source**

![](./media/dettect_add_data_source.png)

We will start by adding in the first data source in the list from LabMeINC.

![](./media/dettect_windows_settings1.png)

1. Type **Windows event logs** into the Data source field. Click the **Add** button to the right.
2. Click on **Date registered** and pick today's date.
3. Click on **Date connected** and pick today's date. In normal circumstances you would select the date you began collecting this data source's logs. 
4. Click **Available for data analytics** This option defaults to `No` but you can change it to `Yes` as LabMeINC is actively monitoring the logs. 
5. Click **Data source enabled** This option defaults to `No` but you can change it to `Yes` as LabMeINC is actively collecting the logs. 
6. Type **Windows** in the **Products** field and then click **Add** - This field provides a way to categorize the data sources you are collecting as certain data sources may have more than one entry depending on the data they provide.
7. The comments field is for internal notes or additional information you would like to include during this exercise. We will not add any notes for this exercise. 

Scroll down to the final section of settings that we can configure for this data source. 

![](./media/dettect_windows_settings2.png)

!!! note
    Please note that every organization will vary in the answers to these questions and your answers will vary between each data sources.

1. Device Completeness - Are all Windows devices sending their logs to the SIEM?
* **Set setting to 3**
2. Data Field Completeness - Are all Windows logs fields being parsed?
* **Set setting to 3**
3. Timeliness - How quickly are the logs received and ingested into the SIEM?
* **Set setting to 4**
4. Consistency - Are logs ingested on a regular basis or are their large delays or outages?
* **Set setting to 2**
5. Retention - How long are the logs retained? 
* **Set setting to 3**

Now that we are finished with configuring the settings for Windows lets proceed to map the next data source.

#### Endpoint Security

Click **Add data source**

![](./media/dettect_add_another_data_source.PNG)

Lets proceed to add the Endpoint Security logs. 

![](./media/dettect_antivirus_settings1.png)

1. Type **Anti-virus** into the Data source field. Click the **Add** button to the right.
2. Click on **Date registered** and pick today's date.
3. Click on **Date connected** and pick today's date. In normal circumstances you would select the date you began collecting this data source's logs. 
4. Click **Available for data analytics** This option defaults to `No` but you can change it to `Yes` as LabMeINC is actively monitoring the logs. 
5. Click **Data source enabled** This option defaults to `No` but you can change it to `Yes` as LabMeINC is actively collecting the logs. 
6. Type **Endpoint Security** in the **Products** field and then click **Add** - This field provides a way to categorize the data sources you are collecting as certain data sources may have more than one entry depending on the data they provide.
7. The comments field is for internal notes or additional information you would like to include during this exercise. We will not add any notes for this exercise. 

Scroll down to the final section of settings that we can configure for this data source. 

![](./media/dettect_antivirus_settings2.png)

!!! note
    Please note that every organization will vary in the answers to these questions and your answers will vary between each data sources.

1. Device Completeness - Are all Windows devices sending their logs to the SIEM?
    **Set setting to 4**
2. Data Field Completeness - Are all Windows logs fields being parsed?
    **Set setting to 1**
3. Timeliness - How quickly are the logs received and ingested into the SIEM?
    **Set setting to 3**
4. Consistency - Are logs ingested on a regular basis or are their large delays or outages?
    **Set setting to 3**
5. Retention - How long are the logs retained? 
    **Set setting to 1**

Now that we are finished with configuring the settings for Endpoint Security lets proceed to map the next data source.

#### Linux

Click **Add data source**

![](./media/dettect_add_another_data_source.PNG)

Lets proceed to add the Linux logs. 

![](./media/dettect_linux_settings1.png)

1. Type **Authentication** into the Data source field. Click the **Add** button to the right.
2. Click on **Date registered** and pick today's date.
3. Click on **Date connected** and pick today's date. In normal circumstances you would select the date you began collecting this data source's logs. 
4. Click **Available for data analytics** This option defaults to `No` but you can change it to `Yes` as LabMeINC is actively monitoring the logs. 
5. Click **Data source enabled** This option defaults to `No` but you can change it to `Yes` as LabMeINC is actively collecting the logs. 
6. Type **Linux** in the **Products** field and then click **Add** - This field provides a way to categorize the data sources you are collecting as certain data sources may have more than one entry depending on the data they provide.
7. The comments field is for internal notes or additional information you would like to include during this exercise. We will not add any notes for this exercise. 

Scroll down to the final section of settings that we can configure for this data source. 

![](./media/dettect_linux_settings2.png)

!!! note
    Please note that every organization will vary in the answers to these questions and your answers will vary between each data sources.

1. Device Completeness - Are all Windows devices sending their logs to the SIEM?
    **Set setting to 3**
2. Data Field Completeness - Are all Windows logs fields being parsed?
    **Set setting to 2**
3. Timeliness - How quickly are the logs received and ingested into the SIEM?
    **Set setting to 2**
4. Consistency - Are logs ingested on a regular basis or are their large delays or outages?
    **Set setting to 3**
5. Retention - How long are the logs retained? 
    **Set setting to 3**

With the Linux logs they are actually collecting more than just **Authentication Logs** from these systems. We will need to add in the additional logs they are collecting from this data source. 

Click **Add data source**

![](./media/dettect_add_another_data_source.PNG)

![](./media/dettect_linux_settings3.png)

1. Type **Web logs** into the Data source field. Click the **Add** button to the right.
2. Click on **Date registered** and pick today's date.
3. Click on **Date connected** and pick today's date. In normal circumstances you would select the date you began collecting this data source's logs. 
4. Click **Available for data analytics** This option defaults to `No` but you can change it to `Yes` as LabMeINC is actively monitoring the logs. 
5. Click **Data source enabled** This option defaults to `No` but you can change it to `Yes` as LabMeINC is actively collecting the logs. 
6. Type **Linux** in the **Products** field and then click **Add** - This field provides a way to categorize the data sources you are collecting as certain data sources may have more than one entry depending on the data they provide.
7. The comments field is for internal notes or additional information you would like to include during this exercise. We will not add any notes for this exercise. 

Scroll down to the final section of settings that we can configure for this data source. 

![](./media/dettect_linux_settings2.png)

!!! note
    Please note that every organization will vary in the answers to these questions and your answers will vary between each data sources.

1. Device Completeness - Are all Windows devices sending their logs to the SIEM?
    **Set setting to 3**
2. Data Field Completeness - Are all Windows logs fields being parsed?
    **Set setting to 2**
3. Timeliness - How quickly are the logs received and ingested into the SIEM?
    **Set setting to 2**
4. Consistency - Are logs ingested on a regular basis or are their large delays or outages?
    **Set setting to 3**
5. Retention - How long are the logs retained? 
    **Set setting to 3**

Now that we are finished with configuring the settings for Linux lets proceed to map the next data source.

#### Network Devices

Click **Add data source**

![](./media/dettect_add_another_data_source.PNG)

Lets proceed to add the Network Device logs. 

![](./media/dettect_network_settings1.png)

1. Type **Network device logs** into the Data source field. Click the **Add** button to the right.
2. Click on **Date registered** and pick today's date.
3. Click on **Date connected** and pick today's date. In normal circumstances you would select the date you began collecting this data source's logs. 
4. Click **Available for data analytics** This option defaults to `No` but you can change it to `Yes` as LabMeINC is actively monitoring the logs. 
5. Click **Data source enabled** This option defaults to `No` but you can change it to `Yes` as LabMeINC is actively collecting the logs. 
6. Type **Network Devices** in the **Products** field and then click **Add** - This field provides a way to categorize the data sources you are collecting as certain data sources may have more than one entry depending on the data they provide.
7. The comments field is for internal notes or additional information you would like to include during this exercise. We will not add any notes for this exercise. 

Scroll down to the final section of settings that we can configure for this data source. 

![](./media/dettect_network_settings2.png)

!!! note
    Please note that every organization will vary in the answers to these questions and your answers will vary between each data sources.

1. Device Completeness - Are all Windows devices sending their logs to the SIEM?
    **Set setting to 2**
2. Data Field Completeness - Are all Windows logs fields being parsed?
    **Set setting to 2**
3. Timeliness - How quickly are the logs received and ingested into the SIEM?
    **Set setting to 3**
4. Consistency - Are logs ingested on a regular basis or are their large delays or outages?
    **Set setting to 1**
5. Retention - How long are the logs retained? 
    **Set setting to 3**

We now have added all of the data sources for LabMeINC and now it is time to save the file and let DeTTECT do its magic. 

![](./media/dettect_save_file.png)

Click **Save YAML file** 


### Visualize Data Sources to the MITRE Framework 


