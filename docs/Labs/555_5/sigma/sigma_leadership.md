# Lab 1.1 - SIGMA Rules - Leadership

## Objectives

- Review logging capabilities and visibility
- Evaluate visibility against the MITRE Attack framework
- Review alert capabilities based on rules
- Review gaps in visibilities and rules

## Exercise Preparation

Log into the Sec-555 VM

- Username: student

- Password: sec555

![](./media/image1.png)


## Exercises

One of the most important exercises that often gets overlooked, is evaluating your organization's visiability. To often security appliances are purchased to fill niche gaps for visibility but rarely is there a cohesive evaluation of all data sources. Lets look at a key data source in almost every organization - **Windows Logs**. 

If you have internet access we will be using the MITRE ATT&CK Navigator for this lab. Try doing so by browsing to the link below.

<a href="https://mitre-attack.github.io/attack-navigator/enterprise/" target="_blank">MITRE ATT&CK Navigator</a>

Next, click on the **+** sign next to the Layer tab.

![](./media/navigator_tab.png)

Next, click on **Open Existing Layer**.

![](./media/navigator_open_layer.png)

Now, click on **Upload from Local**.

![](./media/navigator_upload.png)

Then navigate to /tmp and select heatmap.json.

![](./media/browse.png)

![](./media/browse1.png)

![](./media/browse2.png)

![](./media/browse3.png)

If you get the warning shown below, click on Okay.

![](./media/browse4.png)

The result will be MITRE Navigator showing a map of the Sigma rule coverage for Windows logs.

![](./media/sigma_mitre.png)


## Lab Conclusion

In the lab you were able to learn how to map out your data source visibility to the Mitre Attack framework. From this you were able to see the value in evaluating the logging capabilities of your data sources to see if they could be enhanced similar to the Windows logs with Sysmon. Finally, you were able to create a heatmap of your alert rules to determine where you lacked alerting or needed additional visibility to detect the evil. 

**Lab 1.1 is now complete**\!
