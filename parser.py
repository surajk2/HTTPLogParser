import re
from operator import itemgetter
import itertools
import time
import collections

c = collections.Counter(totalPageCount = 0, totalFailureCount = 0)
col_count = collections.Counter(c)

listOfMethod = ['GET', 'POST', 'PUT', 'DEL', 'PATCH', 'HEAD', 'OPTIONS', 'CONNECT', 'PROPFIND', 'TRACE']

HOST = r'^(?P<host>.*?)'
SPACE = r'\s'
IDENTITY = r'\S+'
USER = r'\S+'
TIME = r'(?P<time>\[.*?\])'
REQUEST = r'\"(?P<request>.*?)\"'
STATUS = r'(?P<status>\d{3})'
SIZE = r'(?P<size>\S+)'

REGEX = HOST+SPACE+IDENTITY+SPACE+USER+SPACE+TIME+SPACE+REQUEST+SPACE+STATUS+SPACE

hostIPDict = {}
page_dict = {}
hostIPPageInfo = {}
top10Host = []

def extract_page(pagestr):
	for method in listOfMethod:
		#print(pagestr)
		index = pagestr.find(method)
		isHTTP = pagestr.find('HTTP')
		if index != -1:
			strPage = pagestr[len(method) + index + 1:]
			if isHTTP != -1:
				return ''.join(itertools.takewhile(lambda x: x != ' ', strPage))
			else:
				return ''.join(itertools.takewhile(lambda x: x != '"', strPage))
	#print(pagestr) // it will print garbage page url
	return pagestr

def parser(log_line):
    match = re.search(REGEX,log_line)
    if match is None:
        # Possibly garbage, ignore it
        results = ('', '', '')
    else:
    	results = ( (match.group('host'), match.group('request') , match.group('status')) )
    return results

# sort in reverse by value and get top 10 hosts making the most request
def list_top10_host(logListofLines):
	hostDict = {}
	#store all host/ip in a list
	hostList = [i.split(' - - ', 1)[0] for i in logListofLines]
	for ip in hostList:
		if hostDict.get(ip) == None:
			hostDict[ip] = 1
		else:
			hostDict[ip] = hostDict[ip] + 1

	res = list(sorted(hostDict.items(), key = itemgetter(1), reverse = True)[:10])
	return res

def print_top10_host():
	print(" The top 10 hosts making the most requests:\n(IP address, number of requests made)\n")
	print(*top10Host, sep = "\n")

def print_top10_requested_pages():
	res = list(sorted(page_dict.items(), key = itemgetter(1), reverse = True)[:10])
	print(" print_top10_requested_pages:\n(Page url, number of requests made)\n")
	for j, TupItem in enumerate(res):
			print("TOP-PAGENo.#" + str(j+1) + " " + str(TupItem[0]) + "," + str(TupItem[1][0]) + "\n")

def print_success_rate():
	successCount = col_count[0] - col_count[1]
	percentageSuccess = (successCount / col_count[0]) * 100
	print("print_success_rate:" + str(percentageSuccess))

def print_failure_rate():
	percentageFail = (col_count[1] / col_count[0]) * 100
	print("print_failure_rate:" + str(percentageFail))

def print_top10_unsuccessful_page_request():
	ListOfPerCentFailTuples = []
	for urlKey, tupValues in page_dict.items():
		(CountPage, FailureCount, FailurePercent) = tupValues
		newTup = (urlKey, FailurePercent) 
		ListOfPerCentFailTuples.append(newTup)
	res = list(sorted(ListOfPerCentFailTuples, key = itemgetter(1), reverse = True)[:10])
	print(" print_top10_unsuccessful_page_request:\n(Page url, percentage)\n")
	print(*res, sep = "\n")

def store_page_info(pageUrl, statusCode):
	col_count[0] += 1
	failureCount = 1
	if statusCode >= '200' and statusCode <= '300':
		failureCount = 0
	col_count[1]+=failureCount
	if page_dict.get(pageUrl) == None:
		page_dict[pageUrl] = (1, failureCount, failureCount*100)
	else:
		page_dict[pageUrl] = (page_dict[pageUrl][0] + 1, page_dict[pageUrl][1] + failureCount, (page_dict[pageUrl][1] + failureCount) / (page_dict[pageUrl][0] + 1)*100)


def isPresentInTop10Host(ip):
	for ipCount in top10Host:
		(ipHost, count) = ipCount
		if ipHost == ip:
			return True
	return False;

def store_ip_page_info_of_top10_ip(ip, pageUrl):
	if hostIPPageInfo.get(ip) == None:
		hostIPPageInfo[ip] = [(1, pageUrl)]
	else:
		for i, dictItem in enumerate(hostIPPageInfo[ip]):
			(count, page_url) = dictItem
			if pageUrl == page_url:
				hostIPPageInfo[ip][i] = (count+1, pageUrl)
				return
		hostIPPageInfo[ip].append((1, pageUrl))

def print_top10_host_with_top5_page_request():
	print("\nprint_top10_host_with_top5_page_request:\n")
	for i, (ipHost, count) in enumerate(top10Host):
		ListOfDictItems = hostIPPageInfo[ipHost]
		res = list(sorted(ListOfDictItems, key = itemgetter(0), reverse = True)[:5])
		print("TOPIP#" + str(i+1) + "-> " + ipHost, "\n")
		for j, TupItem in enumerate(res):
			print("PAGENo.#" + str(j+1) + " " + str(TupItem[::-1]) + "\n")
		print("*************************************************************")

def reader(filename):
	with open(filename) as f:
		logListofLines = f.readlines()
		#print(len(logListofLines))
	return logListofLines

def validate(urlStr):
	spacecount = 0;
	for i in urlStr:
		if i == ' ':
			spacecount+=1
	if spacecount >= 2:
		return True
	else:
		return False

if __name__ == '__main__':

	lisOfLines = reader('access_log_Aug95')

	val = input("Enter 7 for option parsing, or press any key for performing all tasks mentioned in the tasklist.txt:")
	#print(val)
	if val == '7':
		start_time = time.time()
		print("Enter 1 : print_top10_requested_pages")
		print("Enter 2 : print_success_rate")
		print("Enter 3 : print_failure_rate")
		print("Enter 4 : print_top10_unsuccessful_page_request")
		print("Enter 5 : print_top10_host")
		inputVal = input()
		if inputVal == '1' or inputVal == '2' or inputVal == '3' or inputVal == '4':
			for i in lisOfLines:
				result = parser(i)
				urlStr = result[1]
				strPage = extract_page(urlStr)
				store_page_info(strPage, result[2])
			#print(col_count[0])
			#print(col_count[1])

		if inputVal == '1':
			print_top10_requested_pages()
		elif inputVal == '2':
			print_success_rate()
		elif inputVal == '3':
			print_failure_rate()
		elif inputVal == '4':
			print_top10_unsuccessful_page_request()
		elif inputVal == '5':
			top10Host = list_top10_host(lisOfLines)
			print_top10_host()
		else:
			print("please enter values from 1 to 5 for option parsing")
		print("--- %s seconds ---" % (time.time() - start_time))
	else:
		start_time = time.time()
		top10Host = list_top10_host(lisOfLines)
		for i in lisOfLines:
			result = parser(i)
			#print(result)

			urlStr = result[1]
			strPage = extract_page(urlStr)
			store_page_info(strPage, result[2])

			if isPresentInTop10Host(result[0]) == True:
				store_ip_page_info_of_top10_ip(result[0], strPage)

		print_top10_requested_pages()
		print("\n")
		print_success_rate()
		print("\n")
		print_failure_rate()
		print("\n")
		print_top10_unsuccessful_page_request()
		print("\n")
		print_top10_host()
		print("\n")
		print_top10_host_with_top5_page_request()
		print("--- %s seconds ---" % (time.time() - start_time))