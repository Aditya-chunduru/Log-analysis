#Aditya Chunduru
#00335780
#Mini project 3: Log Analysis
#CIS 153 L8
'''Program description: This program takes apache server log file as input and provides analytics on resources and requesters. 
There are two primary functions: 
* read_log_file: takes file_path as a parameter and parses the log file using regex. It stores dict data type to store requesters, resources,
requesters to the resources and vice versa. 

* print_results: takes dict data type objects created by read_log_file and produces log analytics. It displays: 
    Most commonly accessed resource
    Access count
    Top requester
    Request count by top requester

    Most common requester
    Requester request count
    Most requested Resources by requester
    Resource request count

'''
#re for regular expression functions.
import re
#pathlib used for checking if a file exists.
import pathlib


#read log file reads the log file and parses the log file using regex.
def read_log_file(file_path):
    #initializing dictionaries for storing IP address information, accessed resources, requester to resoruce mapping info
    requesters = {}
    resources = {}
    requester_to_resources = {}
    resource_to_requesters = {}

    #regular expresion for apache server log format by extracting the IP address, URI and HTTP.  
    # Refer to Apache documentation for details: https://httpd.apache.org/docs/2.4/logs.html
    # sample line in log file: 
    #64.242.88.10 - - [07/Mar/2004:16:06:51 -0800] "GET /twiki/bin/rdiff/TWiki/NewUserTemplate?rev1=1.3&rev2=1.2 HTTP/1.1" 200 4523
    #cr020r01-3.sac.overture.com - - [11/Mar/2004:13:06:17 -0800] "GET /twiki/bin/view/Know/WebNotify HTTP/1.0" 200 4472
    #64-249-27-114.client.dsl.net - - [11/Mar/2004:14:53:12 -0800] "GET /SpamAssassin.html HTTP/1.1" 200 7368

    #pattern_of_log = re.compile(r'(\d+\.\d+\.\d+\.\d+) - - \[.*?\] "(.*?) (.*?) HTTP/\d\.\d"')
    #regex documentation
    # for ip address: '(.+\..+\..+) ; .+ means 1 or more of any character; \. means literal '.'  
    # for date and time: \[.*?\] ; \[ means look for [ ; * means look for 0 or more characters. ? means 0 or 1 characters only.
    # is an escape character for literal brackets. Literal question mark followed by the backslash 
    # for get request and URI: (.*?) (.*?) ; 
    # for HTTP status code: HTTP/\d\.\d ;
    pattern_of_log = re.compile(r'(.+\..+\..+) - - \[.*?\] "(.*?) (.*?) HTTP/\d\.\d"')

#Specified log file opened in read mode and parse the log file in for loop line by line.
    with open(file_path, 'r') as file:
        for line in file:
            #Uses the regular expression patttern to search for a match.
            match = pattern_of_log.search(line)
            #match finding in log file line
            if not match:
                #current line didn't match regex. Log for verification
                print(f"Skipping invalid entry {line}")
                continue
            #found match 
            #tuple unpacking which assigns each element of the tuple returned by match.groups to ip(first element of tuple which connects to the IP address), 
            # method(element 2 corresponding to HTTP) 
            # and uri(element 3 corresponding to the URI accessed in the HTTP request)
            ip, method, uri = match.groups()
            uri.lower()
            #omit URI parameters; first parameter starts with '?' followed by '&' for additional parameters. 
            # extract URI resource portion only by finding '?' position in the string.
            posUriParam = uri.find("?")
            if posUriParam > 0:
                uri = uri[0: posUriParam]
            print(f"captured URI: {uri}")


                # Resource access count
            resources[uri] = resources.get(uri, 0) + 1

                # Map resource to requester
            if uri in resource_to_requesters:
                    resource_to_requesters[uri].append(ip)
            else:
                    resource_to_requesters[uri] = [ip]

                # Requester access count
            requesters[ip] = requesters.get(ip, 0) + 1

                # Map requester to resources
            if ip in requester_to_resources:
                    requester_to_resources[ip].append(uri)
            else:
                requester_to_resources[ip] = [uri]


    return requesters, resources, requester_to_resources, resource_to_requesters

#print_results: takes dict data type objects created by read_log_file and produces log analytics.

def print_results(requesters, resources, requester_to_resources, resource_to_requesters):

    print(f"\nHere are the log analysis resuts: ")

    #checks if resources or requesters are empty.
    if not resources or not requesters:
        print("No valid entries found in the log file")
        return

    # log analysis for top resource - resource name, count, top requestor.
    #Most_common_resource searches for the key with the highest value in the resources dictionary.
    most_common_resource = max(resources, key=resources.get)

    #Resource access count = resources[most_common_resource] gets the value of access count  
    #associated with the most common accessed resource.
    resource_access_count = resources[most_common_resource]

    #Top_requester_for_resource = resource_to_requesters .get(most_common_resource, []) gets  the list of requesters 
    #who have accessed the most commonly accessed resource from the  resource_to_requesters dictionary.
    requesters_for_top_resource = resource_to_requesters.get(most_common_resource, [])
    #print(f"Value of requesters_for_top_resource: {requesters_for_top_resource}")

    #Check if a resource is not found in the dictionary, it defaults to an empty list. 
    if requesters_for_top_resource:
        # get top requester for resource. 
        top_requester_for_resource = max(requesters_for_top_resource, key=requesters.get)
       # print(f"Value of top_requester_for_resource: {top_requester_for_resource} ")

       # Get count for resource by top requester 
        top_requester_count_for_resource = requesters_for_top_resource.count(top_requester_for_resource)
        #print(f"Value of top_requester_count_for_resource: {top_requester_count_for_resource} ")
    else:
        top_requester_for_resource = "N/A"
        top_requester_count_for_resource = "N/A"

    # Print log analysis results for resources
    print(f"Most commonly accessed resource: {most_common_resource}")
    print(f"Access count: {resource_access_count}")
    print(f"Top requester: {top_requester_for_resource}")
    print(f"\nRequest count by top requester: {top_requester_count_for_resource}")

    # Log analysis for top requester - requester, count, top resource.
    
    #Get most common requester among list of requesters
    most_common_requester = max(requesters, key=requesters.get)
    #Get request count for the top requester
    requester_request_count = requesters[most_common_requester]
    #Get the list of resources requested most by top requester.
    resources_for_top_requester = requester_to_resources.get(most_common_requester, [])
    #print(f"Value of resources_for_top_requester: {resources_for_top_requester} ")

    if resources_for_top_requester:
        #Get most requested resource by top requester
        most_requested_resource_by_requester = max(resources_for_top_requester, key=resources.get)
        #Get resource request count.
        resource_request_count = resources_for_top_requester.count(most_requested_resource_by_requester)
    else:
        most_requested_resource_by_requester = "N/A"
        resource_request_count = "N/A"

    #Print log analysis results for requester.
    print(f"\nMost common requester: {most_common_requester}")
    print(f"Requester request count: {requester_request_count}")
    print(f"Most requested Resources by requester: {most_requested_resource_by_requester}")
    print(f"Resource request count: {resource_request_count}")

#checks if the script is being run as a main program
def main():

    log_file_path = pathlib.Path ("C:\\Users\\adich\\OneDrive\\Documents\\Programming for IT\\Mini Project 3\\access_log")
    print(f"This is the log file currently being used to analyze: {log_file_path} ")
    #print("If you want to change the log file to be analyzed, enter 1 and if not, enter 2.")
    print("Welcome to log file analyzer:")
    print("1: Enter a new log file path.")
    print("2: Keep the default log file.")
    choice = input("Select your choice: ")

    if choice == '1': 
        log_file_path = input("Enter a log file path to analyze: ")
        filecheck = pathlib.Path(log_file_path)
        if filecheck.exists():
            print("Log file exists; continuing to analyze.")
        else:
            print (f"log file not found: {log_file_path}")

    requesters, resources, requester_to_resources, resource_to_requesters = read_log_file(log_file_path)
    print_results(requesters, resources, requester_to_resources, resource_to_requesters)

main()