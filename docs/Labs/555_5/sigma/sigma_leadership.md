# Lab 1.1 - SIGMA Rules - Leadership

## Objectives

- Learn how to map out your visibility in your environment

- Review logging capabilities and visibility

- Evaluate visibility against the MITRE Attack framework

- Review alert capabilities based on your SIGMA rules

## Exercise Preparation

Log into the Sec-555 VM

- Username: student

- Password: sec555

![](./media/image1.png)


## Exercises

### Learn how to map out your visability in your environment
One of the most important exercises that often gets overlooked, is evaluating your organization's visiability. To often security appliances are purchased to fill niche gaps for visibility but rarely is there a cohesive evaluation of all data sources. An amazing tool that can help us perform this task is DeTT&CT. 

!!! note
    You can find more information about this tool as well as guides for installing it in your environment by following the link below. 
    
    `https://github.com/rabobank-cdc/DeTTECT`

Lets walkthrough how you can leverage this tool to provide a true visibility mapping against the MITRE Attack framework. The first step is to click on `Data Sources`.

![](2020-07-01-23-08-11.png)

Select `New file`

![](./media/2020-07-02-11-51-58.png)

Click on `Add Data Source`

![](./media/2020-07-02-11-52-43.png)

You will now have several fields to define what type of data is being collected and to what level logging is being used. 

![](./media/2020-07-02-11-55-54.png)

1. This field contains a wide variety of data sources. You can start typing and it will autocomplete. For this lab we are focusing on Windows logs so we selected Windows Event Logs. 
2. You have the option to define when you registered the data in DeTT&CT
3. You also have the option to define when you started collecting the logs for this data source. 
4. This option defaults to `No` but you can change it to `Yes` if you are actively monitoring the logs. 
5. This allows you to indeicate if you are collecting the logs.
6. This field is optional but it makes it nice to define what sources you are receiving the logs from.  
7. The comments field is for internal notes or additional information you would like to include during this exercise. 

The final section allows us to define the quality of the data that we are collectin. Please note these are qualitative fields so use your best judgement.

![](./media/2020-07-02-12-09-18.png)

1. Device Completeness - Are all Windows devices sending their logs to the SIEM?
2. Data Field Completeness - Are all Windows logs fields being parsed?
3. Timeliness - How quickly are the logs received and ingested into the SIEM?
4. Consistency - Are logs ingested on a regular basis or are their large delays or outages?
5. Retention - How long are the logs retained? 

Please note that every organization will vary in the answers to these questions and your answers will vary between you data sources. When finished modifying these fields `click Add`. 

Now that we have the Windows logs defined as a data source we will generate the YAML file by clicking `Save YamL File`. This will save the file to the input directory that you wil have setup when installing DeTT&ct. 

![](./media/2020-07-02-12-16-49.png)

You will then run the following command to create the .json file we will use to map this data source agianst the MITRE Attack framework. 

```python
python /opt/DeTTECT/dettect.py ds -fd input/data-sources-traditional.yaml -l
```

If you browse to the output folder that you specified when setting up DeTT&ct, you will now have a .json file that we can use to visualize the Windows data source against the MITRE Attack framework. Browse to the following URL with this file. 

`https://mitre-attack.github.io/attack-navigator/enterprise/`

At this site you can `click the plus sign` at the top of the website to add a new layer. Then `click Open Existing Layer`. This will give you the option to Upload from a local file. You will need to browse to the location of the .json file you created and select it and click open. 

![](./media/2020-07-02-13-27-00.png)

When you open this file it will now take the data source information that you provided for the data source and map it to the MITRE Attack framework. So for our example we have followed these steps and here is what we see. 

![](./media/2020-07-02-13-30-04.png)

As you can see the darker the purple the more visibility we have for detecting the specific attack. 

### Review logging capabilities and visibility

Windows Event logs are a common data source most organizations have. While they do provide visibility it begs the question if there is more that can be done to increase the detection capabilities. 
 
System Monitor (Sysmon) is a Windows system service and device driver that, once installed on a system, remains resident across system reboots to monitor and log system activity to the Windows event log. Below is an updated DeTTect data source list now that we have Sysmon running on our Windows systems. 

![](./media/2020-07-02-13-40-44.png)

As you can see Sysmon gives us eight additional data sources. When we began to add in the additional data sources, we leveraged the Products field to differentiate where we were gainng the visibility. Let us compare the difference now. 

Here is our initial Windows Event logs.

![](./media/2020-07-02-13-43-40.png)

Now here is Windows Event logs with the additional Sysmon data sources. 

![](./media/2020-07-02-13-44-41.png)

Clearly, adding in the Sysmon data sources for our Windows logs add a major jump in visibility. This simple process is a great way to show the value of making changes to the logging levels or capabilities of the data sources. When walking through this exercise it would be a great time to evaluate the logging capabilities of each data source to see if there were opportunities to gain additional visibility in the logs that you are collecting. 


### Review alert capabilities based on your rules

The final step is to evaluate the alert rules in place for your data sources. To often organizations will excel in having the needed visibility to detect threats but do not have the appropriate rules to actually alert when a threat is present. Thankfully, we can leverage a tool called `Sigmac` to create heatmap of our rules mapped to the Mitre Attack framework. 

Open a terminal window in the student VM and run the following commands to generate the heatmap. 

```yaml
cd /lab/sigma/elastalert

sudo bash convert.sh
```

The script ran through all of the Sigma rules provided by Sigmac and converted them to ElastAlert rules. It then takes the rules and tests them before putting them into a Production Rules folder. The final step of the script creates a heatmap of the rules against the Mitre Attach framework. 

You should now have a heatmap.json file located in `/lab/sigma/elastalert`. You can now take this file and open it in the Att&ck Navigator that we have been using to show our data source visibility. Below is the alert coverage the SIGMAC tool provided us based on the SIGMA rules we had. 

![](./media/2020-07-02-14-04-15.png)

This is very helpful when trying to evaluate what alert rules you have in place and you can quickly flip back and forth between your data source visibility layers to determine if you have the data to be able to create detection rules agianst. 

In the end these exercises will take some effort to complete in your own environment but it is one of the best ways to map your actual detection capbailities against a security framework. It also provides a road map for you to show gaps in your armor and provide justification for changes in logging and visibility. 

## Lab Conclusion

In the lab you were able to learn how to map out your data source visibility to the Mitre Attack framework. From this you were able to see the value in evaluating the logging capabilities of your data sources to see if they could be enhanced similar to the Windows logs with Sysmon. Finally, you were able to create a heatmap of your alert rules to determine where you lacked alerting or needed additional visibility to detect the evil. 

**Lab 1.1 is now complete**\!
