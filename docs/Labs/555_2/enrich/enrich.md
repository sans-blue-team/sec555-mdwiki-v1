# Lab Enrich

## Objectives

- Understand log enrichment

- Build process for adding context

- Identify sources for context

- Use context for false positive reduction


## Exercise Preparation

Log into the Sec-555 VM

- Username: student

- Password: sec555

![](./media/image1.png)

For this lab you will be using the IDS alert logs below:

**EXE Download Alert**

```bash
[1:2000419:18] ET POLICY PE EXE or DLL Windows file download [Classification: Potential Corporate Privacy Violation] [Priority: 1]: <sodev-eth1-1> {TCP} 74.125.159.56:80 -> 192.168.2.39:49339
```

**PDF alert**

```bash
[1:2017899:3] ET CURRENT_EVENTS Possible PDF Dictionary Entry with Hex/Ascii replacement [Classification: A Network Trojan was detected] [Priority: 1]: <sodev-eth1-1> {TCP} 54.161.95.242:80 -> 192.168.2.39:49247
```

Your goal is to try and identify if any of these alerts are supsicious or malicious in nature.

## Exercises

### Identify available fields

Part of a SIEM is establishing context so that analysts can hypothesize and build a storyline of what may be happening. Often the process is thought to involve manual correlation. Yet, you can build context into your logs directly. Sometimes context can be at search time, and other times it needs to be part of the logs for use with automated alerting.

The first step in log enrichment is to identify what fields are available. The list of fields is necessary to see what options there are for enrichment. Open a command prompt and then run the below command to see what fields are available.

```bash
logstash -f /labs/enrich/field_list.conf
```

!!! note
    The configuration file **field_list.conf** uses **grok** to parse fields from a Snort IDS alert. You could also look at the alert and figure out what fields were available by looking at the data. However, in a production environment you would need to parse the log before enriching it.

The output should look as follows:

```bash
{
           "source_ip" => "54.161.95.242",
                 "gid" => 1,
                 "sid" => 2017899,
      "destination_ip" => "192.168.2.39",
         "source_port" => 80,
            "sequence" => 0,
                 "rev" => "3",
           "interface" => "sodev-eth1-1",
      "classification" => "A Network Trojan was detected",
            "protocol" => "TCP",
    "destination_port" => 49247,
            "priority" => "1",
                "host" => "logstash",
          "@timestamp" => 2020-07-06T22:23:09.686Z,
            "@version" => "1",
               "alert" => "ET CURRENT_EVENTS Possible PDF Dictionary Entry with Hex/Ascii replacement "
}
{
           "source_ip" => "74.125.159.56",
                 "gid" => 1,
                 "sid" => 2000419,
      "destination_ip" => "192.168.2.39",
         "source_port" => 80,
            "sequence" => 0,
                 "rev" => "18",
           "interface" => "sodev-eth1-1",
      "classification" => "Potential Corporate Privacy Violation",
            "protocol" => "TCP",
    "destination_port" => 49339,
            "priority" => "1",
                "host" => "logstash",
          "@timestamp" => 2020-07-06T22:23:09.686Z,
            "@version" => "1",
               "alert" => "ET POLICY PE EXE or DLL Windows file download "
}
```

!!! note
    The @timestamp will reflect the time you perform the command. It will not match the output in any of the commands during this lab.

Based on the output above the following fields are available: source_ip, destination_ip, source_port, destination_port, protocol, sid, gid, rev, priority, alert, interface, classification, and sequence.

### Perform basic geo enrichment

Given the fields found, we need to identify areas to add context to the logs. IP addresses can be useful to use for geo information. Run Logstash with the configuration file below to add geoip information to the logs.

```bash
logstash -f /labs/enrich/geoip.conf
```

The output from this command should be similar to below:

```bash
{
      "classification" => "Potential Corporate Privacy Violation",
            "@version" => "1",
           "source_ip" => "74.125.159.56",
                "host" => "logstash",
                 "rev" => "18",
            "priority" => "1",
         "source_port" => 80,
                 "gid" => 1,
     "destination_geo" => {},
            "sequence" => 0,
            "protocol" => "TCP",
          "source_geo" => {
                    "ip" => "74.125.159.56",
              "latitude" => 37.419200000000004,
                "as_org" => "Google Inc.",
         "country_code3" => "US",
              "location" => {
            "lat" => 37.419200000000004,
            "lon" => -122.0574
        },
           "postal_code" => "94043",
        "continent_code" => "NA",
          "country_name" => "United States",
           "region_code" => "CA",
             "city_name" => "Mountain View",
              "dma_code" => 807,
                   "asn" => 15169,
              "timezone" => "America/Los_Angeles",
         "country_code2" => "US",
           "region_name" => "California",
             "longitude" => -122.0574
    },
          "@timestamp" => 2020-07-06T22:42:08.295Z,
           "interface" => "sodev-eth1-1",
      "destination_ip" => "192.168.2.39",
               "alert" => "ET POLICY PE EXE or DLL Windows file download ",
    "destination_port" => 49339,
                 "sid" => 2000419
}
{
      "classification" => "A Network Trojan was detected",
            "@version" => "1",
           "source_ip" => "54.161.95.242",
                "host" => "logstash",
                 "rev" => "3",
            "priority" => "1",
         "source_port" => 80,
                 "gid" => 1,
     "destination_geo" => {},
            "sequence" => 0,
            "protocol" => "TCP",
          "source_geo" => {
                    "ip" => "54.161.95.242",
              "latitude" => 39.0481,
                "as_org" => "Amazon.com, Inc.",
         "country_code3" => "US",
              "location" => {
            "lat" => 39.0481,
            "lon" => -77.4728
        },
           "postal_code" => "20149",
        "continent_code" => "NA",
          "country_name" => "United States",
           "region_code" => "VA",
             "city_name" => "Ashburn",
              "dma_code" => 511,
                   "asn" => 14618,
              "timezone" => "America/New_York",
         "country_code2" => "US",
           "region_name" => "Virginia",
             "longitude" => -77.4728
    },
          "@timestamp" => 2020-07-06T22:42:08.295Z,
           "interface" => "sodev-eth1-1",
      "destination_ip" => "192.168.2.39",
               "alert" => "ET CURRENT_EVENTS Possible PDF Dictionary Entry with Hex/Ascii replacement ",
    "destination_port" => 49247,
                 "sid" => 2017899
}
```

At this point, basic geoip information is now appended to the logs. The geoip information adds more context about these alerts. For example, the **ET POLICY PE EXE or DLL Windows file download** shows an external IP of **74.125.159.56**. The geoip information shows it is in **Mountain View, California US** and the entity behind the external IP is **Google Inc.**. The **ET CURRENT_EVENTS Possible PDF Dictionary Entry with Hex/Ascii replacement** shows an external IP of **54.161.95.242**. The geoip information shows it is in **Ashburn, VA US** and the entity behind the external IP is **Amazon.com, Inc.**.

At this point there still is not enough information to decide if either of these alerts are malicious or suspicious. The external IP addresses could belong to Google or Amazon. However, they also could belong to someone using Google or Amazon's hosted cloud environments.

## Lab Conclusion



**Lab 1.1 is now complete**\!
