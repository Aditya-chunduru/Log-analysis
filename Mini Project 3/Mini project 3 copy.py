#Aditya Chunduru
#00335780
#Mini project 3: Log Analysis
#CIS 153 L8
#Program description: process of getting data from an apache server log

import re
#pathlib used for checking if a file exists.
import pathlib
def read_log_file(file_path):
    #initializing dictionaries for storing IP address information, accessed resources, requester to resoruce mapping info
    requesters = {}
    resources = {}
    requester_to_resources = {}
    resource_to_requesters = {}

    #regular expresion for apache server log format by extracting the IP address, HTTP and URI.  
    pattern_of_log = re.compile(r'(\d+\.\d+\.\d+\.\d+) - - \[.*?\] "(.*?) (.*?) HTTP/\d\.\d"')
   
#Specified log file opened in read mode
    with open(file_path, 'r') as file:
        for line in file:
            #Uses the regular expression patttern to search for a match in the specified log file. 
            match = pattern_of_log.search(line)
            #match finding in log file line
            if not match:

                print(f"Skipping invalid entry {line}")
                continue 
            #tuple unpacking which assigns each element of the tuple returned by match.groups to ip(first element of tuple which connects to the IP address), 
            # method(element 2 corresponding to HTTP) 
            # and uri(element 3 corresponding to the URI accessed in the HTTP request)
            ip, method, uri = match.groups()
            uri.lower()
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

def print_results(requesters, resources, requester_to_resources, resource_to_requesters):
    print(f"\nHere are the log analysis resuts for: {log_file_path}")
    if not resources or not requesters:
        print("No valid entries found in the log file")
        return

    most_common_resource = max(resources, key=resources.get)
    resource_access_count = resources[most_common_resource]
    top_requester_for_resource = resource_to_requesters.get(most_common_resource, [])

    if top_requester_for_resource:
        top_requester_for_resource = max(top_requester_for_resource, key=requesters.get)
        top_requester_count = requesters[top_requester_for_resource]
    else:
        top_requester_for_resource = "N/A"
        top_requester_count = "N/A"

    print(f"Most commonly accessed resource: {most_common_resource}")
    print(f"Access count: {resource_access_count}")
    print(f"Top requester: {top_requester_for_resource}")
    print(f"\nRequest count by top requester: {top_requester_count}")

    most_common_requester = max(requesters, key=requesters.get)
    requester_request_count = requesters[most_common_requester]
    most_requested_resource_by_requester = requester_to_resources.get(most_common_requester, [])

    if most_requested_resource_by_requester:
        most_requested_resource_by_requester = max(requester_to_resources[most_common_requester], key=resources.get)
        resource_request_count = resources[most_requested_resource_by_requester]
    else:
        most_requested_resource_by_requester = "N/A"
        resource_request_count = "N/A"

    print(f"\nMost common requester: {most_common_requester}")
    print(f"Requester request count: {requester_request_count}")
    print(f"Most requested Resources by requester: {most_requested_resource_by_requester}")
    print(f"Resource request count: {resource_request_count}")

#checks if the script is being run as a main program
if __name__ == "__main__":
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