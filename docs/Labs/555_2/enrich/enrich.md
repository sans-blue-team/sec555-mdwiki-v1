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

!!! note
	The geoip.conf configuration file uses Logstash with the geoip plugin to pull in city, state, country, and ASN information. If you are curious and wish to see the full configuration run this command: code /labs/enrich/geoip.conf

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

### Pull in DNS Query

Next, run Logstash using the dns.conf configuration file to further enrich the IDS alerts. Run the command below to add a query field to the IDS alerts.

```bash
logstash -f /labs/enrich/dns.conf
```

!!! note
	The dns.conf configuration file uses Logstash with the **elasticsearch** plugin to pull in the DNS **query** from historical DNS logs. It does this by looking for the most recent DNS query reponse that had an external IP from the IDS alert in an **answers** field. If you are curious and wish to see the full configuration run this command: code /labs/enrich/dns.conf

The output should now look like below.

```bash
{
    "destination_port" => 49339,
            "sequence" => 0,
           "source_ip" => "74.125.159.56",
           "interface" => "sodev-eth1-1",
               "alert" => "ET POLICY PE EXE or DLL Windows file download ",
          "source_geo" => {
              "dma_code" => 807,
                "as_org" => "Google Inc.",
              "location" => {
            "lon" => -122.0574,
            "lat" => 37.419200000000004
        },
             "longitude" => -122.0574,
                    "ip" => "74.125.159.56",
           "postal_code" => "94043",
         "country_code3" => "US",
           "region_code" => "CA",
                   "asn" => 15169,
             "city_name" => "Mountain View",
        "continent_code" => "NA",
         "country_code2" => "US",
              "timezone" => "America/Los_Angeles",
              "latitude" => 37.419200000000004,
          "country_name" => "United States",
           "region_name" => "California"
    },
            "priority" => "1",
                "host" => "logstash",
            "protocol" => "TCP",
            "@version" => "1",
                 "gid" => 1,
                "tags" => [
        [0] "internal_destination",
        [1] "external_source"
    ],
                 "sid" => 2000419,
         "source_port" => 80,
      "destination_ip" => "192.168.2.39",
      "classification" => "Potential Corporate Privacy Violation",
                 "rev" => "18",
     "destination_geo" => {},
               "query" => "dl.google.com",
          "@timestamp" => 2020-07-09T22:44:21.312Z
}
{
    "destination_port" => 49247,
            "sequence" => 0,
           "source_ip" => "54.161.95.242",
           "interface" => "sodev-eth1-1",
               "alert" => "ET CURRENT_EVENTS Possible PDF Dictionary Entry with Hex/Ascii replacement ",
          "source_geo" => {
              "dma_code" => 511,
                "as_org" => "Amazon.com, Inc.",
              "location" => {
            "lon" => -77.4728,
            "lat" => 39.0481
        },
             "longitude" => -77.4728,
                    "ip" => "54.161.95.242",
           "postal_code" => "20149",
         "country_code3" => "US",
           "region_code" => "VA",
                   "asn" => 14618,
             "city_name" => "Ashburn",
        "continent_code" => "NA",
         "country_code2" => "US",
              "timezone" => "America/New_York",
              "latitude" => 39.0481,
          "country_name" => "United States",
           "region_name" => "Virginia"
    },
            "priority" => "1",
                "host" => "logstash",
            "protocol" => "TCP",
            "@version" => "1",
                 "gid" => 1,
                "tags" => [
        [0] "internal_destination",
        [1] "external_source"
    ],
                 "sid" => 2017899,
         "source_port" => 80,
      "destination_ip" => "192.168.2.39",
      "classification" => "A Network Trojan was detected",
                 "rev" => "3",
     "destination_geo" => {},
               "query" => "trackmypackage-com.biz",
          "@timestamp" => 2020-07-09T22:44:21.311Z
}
```

At this point, the IDS alerts have more significant context. For example, one alert deals with traffic to **dl.google.com** which is hosted on an external IP registered to an ASN of **Google Inc.**. **dl.google.com** is Google's download site for anyone wishing to download software like Google Chrome, Google Drive Sync, as well as other Google software. As a result, the alert dealing with Google is likely benign.

The other alert reflects traffic going to **trackmypackage-com.biz** which is hosted on an external IP registered to an ASN of **Amazon.com Inc**. **trackymypackage-com.biz** looks like a suspicious domain due to having **-com.biz** rather than simply **.com** or **.biz**. The ASN allows a possible hypothesis that this is a server hosted within Amazon's AWS environment.

## Lab Conclusion

**Enrichment Lab is now complete**\!
