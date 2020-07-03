# Lab 1.1 - SIGMA Rules - Security Engineer

## Objectives

- Review SIGMA rule structure

- Convert rules to different alerting platforms

- Learn how to add context to rules

- Establish a process for mass rule management


## Exercise Preparation

Log into the Sec-555 VM

- Username: student

- Password: sec555

![](./media/image1.png)

## Exercises

### Review SIGMA rule structure

SIGMA provides a structure by which detection rules can be written in a generic form. The example below shows the core structure of a SIGMA rule. 

```yaml
title: Suspicious Scripting in a WMI Consumer
id: fe21810c-2a8c-478f-8dd3-5a287fb2a0e0
status: experimental
description: Detects suspicious scripting in WMI Event Consumers
references:
    - https://in.security/an-intro-into-abusing-and-identifying-wmi-event-subscriptions-for-persistence/
    - https://github.com/Neo23x0/signature-base/blob/master/yara/gen_susp_lnk_files.yar#L19
date: 2019/04/15
tags:
    - attack.t1086
    - attack.execution
logsource:
   product: windows
   service: sysmon
detection:
    selection:
        EventID: 20
        Destination:
            - '*new-object system.net.webclient).downloadstring(*'
            - '*new-object system.net.webclient).downloadfile(*'
            - '*new-object net.webclient).downloadstring(*'
            - '*new-object net.webclient).downloadfile(*'
            - '* iex(*'
            - '*WScript.shell*'
            - '* -nop *'
            - '* -noprofile *'
            - '* -decode *'
            - '* -enc *'
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Administrative scripts
level: high
```

**Key Components**

- Tags - Includes the MITRE Attack mappings
- Log Source - Defines the type of log data this rule is written for
- Detection - Provides the core of the rule by including the syntax that the rule will alert on
- Fields - Lists the field names that will be queried in the detection syntax 
- Level - Sets a user-defined rating on the severity if this rule is triggered

Below is the rule after it has been converted to ElastAlert format.

```yaml
alert:
- debug
description: Detects suspicious scripting in WMI Event Consumers
filter:
- query:
    query_string:
      query: (winlog.channel:"Microsoft\-Windows\-Sysmon\/Operational" AND winlog.event_id:"20" AND Destination.keyword:(*new\-object\ system.net.webclient\).downloadstring\(* OR *new\-object\ system.net.webclient\).downloadfile\(* OR *new\-object\ net.webclient\).downloadstring\(* OR *new\-object\ net.webclient\).downloadfile\(* OR *\ iex\(* OR *WScript.shell* OR *\ \-nop\ * OR *\ \-noprofile\ * OR *\ \-decode\ * OR *\ \-enc\ *))
index: winlogbeat-*
name: fe21810c-2a8c-478f-8dd3-5a287fb2a0e0_0
priority: 2
realert:
  minutes: 0
type: any
```

As you can see, this rule still contains the core information provided by the SIGMA rule above, but the format has changed drastically.

**Key Components**

- Filter - Contains the necessary Lucene syntax to match the information provided in the Detection section of the SIGMA rule
- Index - Points at the index the rule should run the filter query against
- Priority - Sets the user-defined rating on the severity of the rule

Key change during the conversion is that the MITRE Attack tags were not carried over to the ElastAlert rule.

### Convert rules to different alerting platforms

While SIGMA provides a standardized structure for detection rules to be written, it requires that rules to be converted to be leveraged by your SIEM. Choose one of the following formats and manually convert the rule. 

**Elasticsearch**

```yaml
cd /lab/sigma

tools/sigmac -I -t es-rule -c tools/config/winlogbeat.yml rules/windows/sysmon/sysmon_wmi_susp_scripting.yml
```

**ElastAlert** 

```yaml
cd /lab/sigma

tools/sigmac -I -t elastalert -c tools/config/winlogbeat.yml rules/windows/sysmon/sysmon_wmi_susp_scripting.yml
```

**Splunk**

```yaml
cd /lab/sigma

/opt/sigma$ tools/sigmac -I -t splunk -c tools/config/splunk-windows.yml rules/windows/sysmon/sysmon_wmi_susp_scripting.yml
```

As you can see as you run the command you receive the converted rule as a text output to the screen. Depending on the solution you chose, you would be able to create the rule in SIEM solution. 

### Learn how to add context to rules

In the first section of this lab, we reviewed a SIGMA rule and compared it to an ElastAlert rule after it had been converted. One of the core differences was that the ElastAlert rule no longer contained the MITRE Attack tags. This is a valuable piece of information. Now let us fix Sigmac to bring over the MITRE tag enrichment. 

```bash
cd /lab/sigma/tools/sigma/backends
code elasticsearch.py
```

Press CTRL + g and then type in 965 

Press Enter

Add the below the line that starts with "realert":

```bash
"mitre": rule_tag,
```

**INFO**: The comma behind rule_tag is required

Save the File

Now that we have modified this file lets go back and rerun the conversion tool for the rule.

**Elasticsearch**

```
cd /lab/sigma
tools/sigmac -I -t es-rule -c tools/config/winlogbeat.yml rules/windows/sysmon/sysmon_wmi_susp_scripting.yml
```

**ElastAlert** 

```
cd /lab/sigma
tools/sigmac -I -t elastalert -c tools/config/winlogbeat.yml rules/windows/sysmon/sysmon_wmi_susp_scripting.yml
```

**Splunk**

```
cd /lab/sigma
/opt/sigma$ tools/sigmac -I -t splunk -c tools/config/splunk-windows.yml rules/windows/sysmon/sysmon_wmi_susp_scripting.yml
```

You should now see an output similar to the ElastAlert rule below that now contains the MITRE Attack tagging which will enrich this alert during threat hunting. 

```yaml
alert:
- debug
description: Detects suspicious scripting in WMI Event Consumers
filter:
- query:
    query_string:
      query: (winlog.channel:"Microsoft\-Windows\-Sysmon\/Operational" AND winlog.event_id:"20" AND Destination.keyword:(*new\-object\ system.net.webclient\).downloadstring\(* OR *new\-object\ system.net.webclient\).downloadfile\(* OR *new\-object\ net.webclient\).downloadstring\(* OR *new\-object\ net.webclient\).downloadfile\(* OR *\ iex\(* OR *WScript.shell* OR *\ \-nop\ * OR *\ \-noprofile\ * OR *\ \-decode\ * OR *\ \-enc\ *))
index: winlogbeat-*
mitre:
- attack.t1086
- attack.execution
name: fe21810c-2a8c-478f-8dd3-5a287fb2a0e0_0
priority: 2
realert:
  minutes: 0
type: any
```

### Establish a process for mass rule management

Now with the ability to not only convert a SIGMA rule to the correct platform but also enrich it via the MITRE attack framework, we are ready to mass convert the rules and start alerting. The challenge we face is that the Sigmac commands will only covert the rules to a single file so we will need to leverage a little scripting to pull this off. 

Below we will walk through the script to point out a few of the functions. The first is the basic setup where you can define the location of the footer file, which contains alerting information that will be appended to the rules as well as where the rules should be placed once converted. 

```python
#!/bin/bash
ALERTENGINE="elastalert"
TEMPLATE="winlogbeat"
FOOTERFILE="/lab/sigma/elastalert/footer.yml"
SIGMAFOLDER="/lab/sigma"
FOLDER="/lab/sigma/rules/windows"
OUTPUTFOLDER="/lab/sigma/elastalert/testing"
MITRECONVERTTOOL="/lab/sigma/elastalert/elastalert2attack"

PRODUCTIONRULEFOLDER="/lab/sigma/elastalert/rules/sigma"
MANUALREVIEWFOLDER="/lab/sigma/elastalert/review/manual"
SLOWRULEFOLDER="/lab/sigma/elastalert/review/slow"

# Enable or disable which steps you want performed
PREREQ=1
CONVERT=1
REMOVEOLDRULES=1
TESTRULES=1
MITREMAP=1
```

This next section does a quick precheck to ensure all the correct files and programs are in place for the script to work.

```python
# Do not change variables below this line unless you know what you are doing
SIGMAC="${SIGMAFOLDER}/tools/sigmac"

# Prerequisite check
if [[ "$PREREQ" == 1 ]]; then
  if [ $(dpkg-query -W -f='${Status}' git 2>/dev/null | grep -c "ok installed") -eq 0 ];
  then
    echo "Installing git"
    apt install -y git
  else
    echo "Git is already installed"
  fi
  if [ $(snap info jq 2>/dev/null | grep -c "installed") -eq 0 ];
  then
    echo "Installing jq"
    snap install jq
  else
    echo "jq is already installed"
  fi
  if [ $(snap info yq 2>/dev/null | grep -c "installed") -eq 0 ];
  then
    echo "Installing yq"
    snap install yq
  else
    echo "yq is already installed"
  fi

  # First, make sure sigma is downloaded
  if [ -d $SIGMAFOLDER ]
  then
    echo "Sigma folder $SIGMAFOLDER exists. Performing git pull..."
    cd $SIGMAFOLDER
    git pull
  else
    echo "Sigma folder does not exists. Performing git clone..."
    mkdir -p $SIGMAFOLDER
    cd $SIGMAFOLDER
    git clone https://github.com/Neo23x0/sigma.git .
  fi
fi
```

Finally, here comes the magic. The script begins to grab each of the SIGMA rules and converts them to a separate ElastAlert rule file. 

```python
if [[ "$CONVERT" == 1 ]]; then
  if [[ "$REMOVEOLDRULES" == 1 ]]; then
    rm -rf $OUTPUTFOLDER/*
  fi
  FILES=$(find $FOLDER -type f)
  for FILE in $FILES
  do
    FILENAME=$(basename $FILE | cut -d"." -f1)
    ID=$(grep "^id:" $FILE | cut -d":" -f2 | cut -d" " -f2)
    OUTPUTFILE="${FILENAME}_${ID}"
    echo "Processing $FILENAME"
    RULEFILE=$(grep -r $ID /lab/sigma/rules/windows | cut -d":" -f1)
    RULEDESCRIPTION=$(cat $RULEFILE | yq r - description)
    RULEREFERENCES=($(cat $RULEFILE | yq r - references))
    APPENDSTRING=""
    for i in "${RULEREFERENCES[@]}"
    do
      if [[ "$i" != "-" ]]; then
        if [[ "$APPENDSTRING" == "" ]]; then
          APPENDSTRING="$i"
        else
          APPENDSTRING="${APPENDSTRING}<br/>$i"
        fi
      fi
    done
    if [ "${#RULEREFERENCES[@]}" -ge 1 ]; then
      DESCRIPTION="${RULEDESCRIPTION}<br/><br/>${APPENDSTRING}"
    fi
    RULETAGS=$(cat $RULEFILE | yq r - tags | cut -d"." -f2)
    SIGMACOUTPUT=""
    SIGMACOUTPUT=$(python3 $SIGMAC -t $ALERTENGINE -c $TEMPLATE $FILE --output $OUTPUTFOLDER/$OUTPUTFILE.yml 2>&1 > /dev/null)
    if [[ "$SIGMACOUTPUT" != "" ]]; then
      echo "Error encountered: $SIGMACOUTPUT"
      rm -f $OUTPUTFOLDER/$OUTPUTFILE.yml
    else
      cat $FOOTERFILE >> $OUTPUTFOLDER/$OUTPUTFILE.yml
      DESCRIPTION=$(echo $DESCRIPTION | tr "'" '"')
      DESCRIPTION=$(sed -e 's/[\\/"]/\\&/g; s/$/\\/' -e '$s/\\$//' <<<"$DESCRIPTION")
      sed -i -e "s|DESCRIPTIONREPLACEME|$DESCRIPTION|" "$OUTPUTFOLDER/$OUTPUTFILE.yml"
      echo " "
    fi
  done
fi
```

With that completed, the script now goes through the process of launching a docker container of ElastAlert. This container will test each rule to ensure that it runs successfully, quickly, and does not return to many false positives. If a rule fails any of these checks, it is moved to a Manual Review Folder or the Slow Rule Folder. Otherwise, the rule is moved directly to the Production Rule Folder.

```python
if [[ "$TESTRULES" == 1 ]]; then
  if [[ "$REMOVEOLDRULES" == 1 ]]; then
    rm -rf $MANUALREVIEWFOLDER/*
    rm -rf $SLOWRULEFOLDER/*
    rm -rf $PRODUCTIONRULEFOLDER/*
  fi
  TESTINGFILES=$(find $OUTPUTFOLDER -type f)
  for FILE in $TESTINGFILES
  do
    FILENAME=$(basename $FILE | cut -d"." -f1)
    echo "Processing $FILENAME"
    TESTOUTPUT=$(docker run -it --rm --network=lab -v /lab/sigma/elastalert/config/elastalert.yaml:/opt/elastalert/elastalert.yaml -v /lab/sigma/elastalert/testing:/opt/elastalert/rules --entrypoint elastalert-test-rule hasecuritysolutions/elastalert:0.2.2 --config /opt/elastalert/elastalert.yaml --formatted-output /opt/elastalert/rules/${FILENAME}.yml | grep writeback)
    echo "File is ${FILENAME}.yml"
    OUTPUT=$(echo $TESTOUTPUT | jq .)
    TIMETAKEN=$(echo $OUTPUT | jq .writeback.elastalert_status.time_taken)
    MATCHES=$(echo $OUTPUT | jq .writeback.elastalert_status.matches)
    HITS=$(echo $OUTPUT | jq .writeback.elastalert_status.hits)
    echo $OUTPUT
    echo "Time taken is $TIMETAKEN"
    if (( $(echo "$TIMETAKEN > 0" | bc -l) )); then
      GO=1
    else
      GO=0
    fi
```

# Lab 1.1 - SIGMA Rules - Security Manager

## Objectives

- Learn how to map out your visability in your environment

- Compare and contrast the difference Sysmon can make

- Evaluate visibility against the MITRE Attack framework

- Review alert capabilities based on your SIGMA rules

## Exercise Preparation

Log into the Sec-555 VM

- Username: student

- Password: sec555

![](./media/image1.png)


## Exercises

### Learn how to map out your visability in your environment
One of the most important exercises that often gets overlooked, is evaluating your organization's visiability. To often security appliances are purchased to fill niche gaps for visibility but rarely is there a cohesive evaluation of all data sources. An amazing tool that can help us perform this task is DeTT&CT. You can find more information about this tool as well as guides for installing it in your environment by following the link below. 

`https://github.com/rabobank-cdc/DeTTECT`

Lets walkthrough how you can leverage this tool to provide a true visibility mapping against the MITRE Attack framework. The first step is to click on Data Sources.

![](2020-07-01-23-08-11.png)

Select New file


### Compare and contrast the difference Sysmon can make
### Evaluate visibility against the MITRE Attack framework
### Review alert capabilities based on your SIGMA rules
## Lab Conclusion



**Lab 1.1 is now complete**\!
