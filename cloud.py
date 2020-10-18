#!/usr/bin/env python3

# cloud.py 
# Location info for Amazon Web Services and Google Cloud Platform datacenters.
#
# Author: K. Walsh <kwalsh@cs.holycross.edu>
# Date: 9 February 2017
# Updated: 16 October 2020 - merged aws.py, gce.py, and cloud.py

"""
You can import and use this in other code like this:
  import cloud
This will define several variables with information about the current machine
where you are running this code. For example:
   cloud.ipaddr: "54.242.85.178"
  cloud.dnsname: "c2-54-242-85-178.compute-1.amazonaws.com"
 cloud.provider: "Amazon AWS/EC2 Cloud"
     cloud.zone: "s-west-1b"
   cloud.region: "s-west-1"
    cloud.title: "US West (N. California)"
     cloud.city: "Palo Alto"
   cloud.coords: (37.44, -122.14)   # this is a pair containing latitude, longitude

You can also run this file in standalone demo mode like this:
  python3 cloud.py
It will print out information about every known EC2 and GCE datacenter, along
with info about the cloud machine where you are running this code, if known.
"""

# Amazon does not seem to publish information about the actual physical
# locations of their AWS EC2 datacenters at all, even though they sometimes use
# suggestive titles like "US East (N. Virginia)". 
#
# The actual street addresses for the data centers are not public, and the
# buildings themselves can be a little difficult to find (see [1] for example).
# Even finding the approximate city or county involves a little guesswork. As
# best I am able, I've compiled below the name of the nearest major city where
# each region's datacenters seem to be housed, and the geographic latitude,
# longitude coordinates for those locations.
#
# Some of the informabion below comes from Turnkey Linux [2]. Those folks are using
# this information as part of their project, but they don't seem to cite their
# sources for this information.
#
# Google is a bit more public about the actual physical locations of their GCP
# GCE datacenters than Amazon, but the location data below is still only an
# approximation.
#
# For both AWS and GCP, each "region" contains several "availability zones",
# each of which in turn contains several "data centers". The data centers are
# the physical buildings that house the enormous number of computers that make
# up Amazon Web Services and Google Cloud Platform, including Elastic Cloud
# Compute (EC2) and Google Compute Engine (GCE).
#
# [1]: https://www.theatlantic.com/technology/archive/2016/01/amazon-web-services-data-center/423147/
# [2]: https://github.com/turnkeylinux/aws-datacenters/blob/master/input/datacenters


# list of all region names
aws_regions = [ # AWS regions
    "us-east-1", "us-east-2", "us-west-1", "us-west-2",
    "af-south-1",
    "ap-east-1", "ap-south-1", "ap-northeast-1", "ap-northeast-2", "ap-southeast-1", "ap-southeast-2",
    "ca-central-1",
    "eu-central-1", "eu-west-1", "eu-west-2", "eu-west-3", "eu-south-1", "eu-north-1",
    "me-south-1",
    "sa-east-1",
]
gcp_regions = [ # GCP regions
    "asia-east1", "asia-east2", "asia-northeast1", "asia-northeast2", "asia-northeast3", "asia-south1", "asia-southeast1", "asia-southeast2",
    "australia-southeast1",
    "europe-north1", "europe-west1", "europe-west2", "europe-west3", "europe-west4", "europe-west6",
    "northamerica-northeast1",
    "southamerica-east1",
    "us-central1", "us-east1", "us-east4", "us-west1", "us-west2", "us-west3", "us-west4",
]
regions = aws_regions + gcp_regions

# official english-language title of each region
region_titles = {
    # AWS regions
    "af-south-1":        "Africa (Cape Town)",
    "ap-east-1":         "Asia Pacific (Hong Kong)",
    "ap-northeast-1":    "Asia Pacific (Tokyo)", 
    "ap-northeast-2":    "Asia Pacific (Seoul)", 
    "ap-south-1":        "Asia Pacific (Mumbai)", 
    "ap-southeast-1":    "Asia Pacific (Singapore)", 
    "ap-southeast-2":    "Asia Pacific (Sydney)", 
    "ca-central-1":      "Canada (Central)", 
    "eu-central-1":      "EU (Frankfurt)", 
    "eu-north-1":        "EU (Stockholm)",
    "eu-south-1":        "EU (Milan)",
    "eu-west-1":         "EU (Ireland)", 
    "eu-west-2":         "EU (London)", 
    "eu-west-3":         "EU (Paris)",
    "me-south-1":        "Middle East (Bahrain)",
    "sa-east-1":         "South America (Sao Paulo)", 
    "us-east-1":         "US East (N. Virginia)", 
    "us-east-2":         "US East (Ohio)", 
    "us-west-1":         "US West (N. California)", 
    "us-west-2":         "US West (Oregon)", 

    # GCP regions
    "asia-east1":               "Eastern Asia-Pacific (Taiwan)",
    "asia-east2":               "Eastern Asia-Pacific (Hong Kong)",
    "asia-northeast1":          "Northeastern Asia-Pacific (Tokyo)",
    "asia-northeast2":          "Northeastern Asia-Pacific (Osaka)",
    "asia-northeast3":          "Northeastern Asia-Pacific (Seoul)",
    "asia-south1":              "Southern Asia-Pacific (Mumbai)",
    "asia-southeast1":          "Southeastern Asia-Pacific (Singapore)",
    "asia-southeast2":          "Southeastern Asia-Pacific (Jakarta)",
    "australia-southeast1":     "Australia (Sydney)",
    "europe-north1":            "Northern Europe (Hamina)",
    "europe-west1":             "Western Europe (St. Ghislain)",
    "europe-west2":             "Western Europe (London)",
    "europe-west3":             "Western Europe (Frankfurt)",
    "europe-west4":             "Western Europe (Eemshaven)",
    "europe-west6":             "Western Europe (Zurich)",
    "northamerica-northeast1":  "North America (Montreal)",
    "southamerica-east1":       "South America (Sao Paulo)",
    "us-central1":              "Central US (Iowa)",
    "us-east1":                 "Eastern US (S. Carolina)",
    "us-east4":                 "Eastern US (N. Virginia)",
    "us-west1":                 "Western US (Oregon)",
    "us-west2":                 "Western US (Los Angeles)",
    "us-west3":                 "Western US (Salt Lake City)",
    "us-west4":                 "Western US (Las Vegas)",
}

# city where each datacenter is located, approximately
region_cities = {
    # AWS regions
    "af-south-1":        "Cape Town",
    "ap-east-1":         "Hong Kong",
    "ap-northeast-1":    "Tokyo",
    "ap-northeast-2":    "Seoul",
    "ap-south-1":        "Mumbai",
    "ap-southeast-1":    "Singapore",
    "ap-southeast-2":    "Sydney",
    "ca-central-1":      "Montreal",
    "eu-central-1":      "Frankfurt",
    "eu-north-1":        "Stockholm",
    "eu-south-1":        "Milan",
    "eu-west-1":         "Dublin", # not sure where exactly
    "eu-west-2":         "London",
    "eu-west-3":         "Paris",
    "me-south-1":        "Bahrain", # not sure where exactly
    "sa-east-1":         "Sao Paulo",
    "us-east-1":         "Charlottesville",
    "us-east-2":         "Columbus",
    "us-west-1":         "Palo Alto",
    "us-west-2":         "Oregon", # not sure where exactly

    # GCP regions
    "asia-east1":               "Changhua County",
    "asia-east2":               "Hong Kong",
    "asia-northeast1":          "Tokyo",
    "asia-northeast2":          "Osaka",
    "asia-northeast3":          "Seoul",
    "asia-south1":              "Mumbai",
    "asia-southeast1":          "Singapore",
    "asia-southeast2":          "Jakarta",
    "australia-southeast1":     "Sydney",
    "europe-north1":            "Hamina",
    "europe-west1":             "St. Ghislain",
    "europe-west2":             "London",
    "europe-west3":             "Frankfurt",
    "europe-west4":             "Eemshaven",
    "europe-west6":             "Zurich",
    "northamerica-northeast1":  "Montreal",
    "southamerica-east1":       "Sao Paulo",
    "us-central1":              "Council Bluffs",
    "us-east1":                 "Berkeley County",
    "us-east4":                 "N. Virginia",
    "us-west1":                 "The Dalles",
    "us-west2":                 "Los Angeles",
    "us-west3":                 "Salt Lake City",
    "us-west4":                 "Las Vegas",
}

# (latitude, longitude) where each datacenter is located, approximately
region_coords = {
    # AWS regions
    "af-south-1":      (-33.93, 18.42),
    "ap-east-1":       (22.28, 114.26),
    "ap-northeast-1":  (35.41, 139.42),
    "ap-northeast-2":  (37.57, 126.98),
    "ap-south-1":      (19.08, 72.88),
    "ap-southeast-1":  (1.37, 103.80),
    "ap-southeast-2":  (-33.86, 151.20),
    "ca-central-1":    (45.50, -73.57),
    "eu-central-1":    (50.1167, 8.6833),
    "eu-north-1":      (59.39, 17.87),
    "eu-south-1":      (45.51, 9.24),
    "eu-west-1":       (53.35, -6.26),
    "eu-west-2":       (51.51, -0.13),
    "eu-west-3":       (48.93, 2.35),
    "me-south-1":      (26.15, 50.47),
    "sa-east-1":       (-23.34, -46.38),
    "us-east-1":       (38.13, -78.45),
    "us-east-2":       (39.96, -83.00),
    "us-west-1":       (37.44, -122.14),
    "us-west-2":       (46.15, -123.88),

    # GCP regions
    "asia-east1":               (24.051796, 120.516135),
    "asia-east2":               (22.29, 114.27),
    "asia-northeast1":          (35.689488, 139.691706),
    "asia-northeast2":          (34.67, 135.44),
    "asia-northeast3":          (37.56, 126.96),
    "asia-south1":              (9.03, 72.84),
    "asia-southeast1":          (1.351231, 103.7073706),
    "asia-southeast2":          (-6.23, 106.79),
    "australia-southeast1":     (-33.77, 150.97),
    "europe-north1":            (60.53923, 27.1112792),
    "europe-west1":             (50.449109, 3.818376),
    "europe-west2":             (51.57, -0.24),
    "europe-west3":             (50.14, 8.58),
    "europe-west4":             (53.4257262, 6.8631489),
    "europe-west6":             (47.40, 8.40),
    "northamerica-northeast1":  (45.47, -73.77),
    "southamerica-east1":       (-23.57, -46.76),
    "us-central1":              (41.261944, -95.860833),
    "us-east1":                 (33.126062, -80.008775),
    "us-east4":                 (39.0115232, -77.4776423),
    "us-west1":                 (45.594565, -121.178682),
    "us-west2":                 (33.9181564, -118.4065411),
    "us-west3":                 (40.75, -112.17),
    "us-west4":                 (36.0639023, -115.2266872),
}


# Amazon mechanism for getting our own external IP address
def aws_get_my_external_ip():
    import requests
    r = requests.get('http://169.254.169.254/latest/meta-data/public-ipv4')
    r.raise_for_status()
    return r.text

# Amazon mechanism for getting our own external DNS hostname
def aws_get_my_dns_hostname():
    import requests
    r = requests.get('http://169.254.169.254/latest/meta-data/public-hostname')
    r.raise_for_status()
    return r.text

# Amazon mechanism for getting our own availability zone
def aws_get_my_zone():
    import requests
    r = requests.get('http://169.254.169.254/latest/meta-data/placement/availability-zone/')
    r.raise_for_status()
    return r.text

# Amazon availability zones have names like us-east-1a or us-east-1b. To get the
# region name, we can just remove the last letter.
def aws_region_for_zone(z):
    lastchar = z[len(z)-1]
    if lastchar >= 'a' and lastchar <= 'z':
        return z[0:len(z)-1]
    else:
        return z

# Amazon mechanism for getting our own internal host name
def gcp_get_my_internal_hostname():
    import requests
    metadata_flavor = {'Metadata-Flavor' : 'Google'}
    r = requests.get('http://metadata.google.internal/computeMetadata/v1/instance/name', headers = metadata_flavor)
    r.raise_for_status()
    return r.text

# Google mechanism for getting our own external IP address
def gcp_get_my_external_ip():
    import requests
    metadata_flavor = {'Metadata-Flavor' : 'Google'}
    r = requests.get('http://metadata.google.internal/computeMetadata/v1/instance/network-interfaces/0/access-configs/0/external-ip', headers = metadata_flavor)
    r.raise_for_status()
    return r.text

# Google mechanism for getting our own zone
def gcp_get_my_zone():
    import requests
    metadata_flavor = {'Metadata-Flavor' : 'Google'}
    r = requests.get('http://metadata.google.internal/computeMetadata/v1/instance/zone', headers = metadata_flavor)
    r.raise_for_status()
    return r.text.split('/')[-1]

# Google availability zones have names like us-east1-a or us-east1-b. To get the
# region name, we can just remove the last letter and the dash.
def gcp_region_for_zone(z):
    lastchar = z[len(z)-1]
    penultimatechar = z[len(z)-2]
    if lastchar >= 'a' and lastchar <= 'z' and penultimatechar == '-':
        return z[0:len(z)-2]
    else:
        return z

# Default values, in case we are not running in the cloud.
dnsname = "localhost"
ipaddr = "127.0.0.1"
provider = None
zone = None
region = None
title = None
city = None
coords = (0, 0)

# Try to figure out information about our own host.
try:
    # First try AWS meta-data service to figure out our own ec2 availability zone and region.
    print("Checking for AWS meta-data...")
    dnsname = aws_get_my_dns_hostname()
    ipaddr = aws_get_my_external_ip()
    zone = aws_get_my_zone()
    region = aws_region_for_zone(zone)
    title = region_titles[region]
    city = region_cities[region]
    coords = region_coords[region]
    provider = "Amazon AWS/EC2 Cloud"
except:
    try:
        # If that fails, next try GCP meta-data service.
        print("Checking for GCP meta-data...")
        dnsname = gcp_get_my_internal_hostname()
        ipaddr = gcp_get_my_external_ip()
        zone = gcp_get_my_zone()
        region = gcp_region_for_zone(zone)
        title = region_titles[region]
        city = region_cities[region]
        coords = region_coords[region]
        provider = "Google GCP/GCE Cloud"
    except:
        # If that fails, give up and just accept the default values.
        pass

# test code
if __name__ == "__main__":

    print("There are %d Amazon Web Services regions." % (len(aws_regions)))
    print("%-16s %-26s %-36s %s, %s" % ("zone", "title", "city", "lat", "lon"))
    for r in aws_regions:
        (lat, lon) = region_coords[r]
        print("%-26s %-40s %-20s %0.2f, %0.2f" % (r, region_titles[r], region_cities[r], lat, lon))

    print("There are %d Google Cloud Platform regions." % (len(gcp_regions)))
    print("%-26s %-40s %-20s %s, %s" % ("zone", "title", "city", "lat", "lon"))
    for r in gcp_regions:
        (lat, lon) = region_coords[r]
        print("%-26s %-40s %-20s %0.2f, %0.2f" % (r, region_titles[r], region_cities[r], lat, lon))

    print("Information about the current host:")
    print("   dnsname: %s" % (dnsname))
    print("    ipaddr: %s" % (ipaddr))
    print("  provider: %s" % (provider))
    print("      zone: %s" % (zone))
    print("    region: %s" % (region))
    print("     title: %s" % (title))
    print("      city: %s" % (city))
    print("    coords: (%s, %s)" % (coords[0], coords[1]))
