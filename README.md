##osquery new table ping
======================

REPO LOCATION: https://github.com/lamskm/osquery

[1]. Instructions to use osquery ping table:

In the forked repo of osquery above, an extension table named ping has been added to osquery.

Three CMakeLists.txt files have been modified (added a line for the ping table code):

https://github.com/lamskm/osquery/blob/master/specs/CMakeLists.txt   
https://github.com/lamskm/osquery/blob/master/osquery/tables/networking/CMakeLists.txt   
https://github.com/lamskm/osquery/blob/master/tests/integration/tables/CMakeLists.txt   

and three files have been added:

https://github.com/lamskm/osquery/blob/master/specs/ping.table   
https://github.com/lamskm/osquery/blob/master/osquery/tables/networking/ping.cpp   
https://github.com/lamskm/osquery/blob/master/tests/integration/tables/ping.cpp  

These 3 changes and 3 files can be downloaded and integrated into an existing osquery repo to build.
And the same invocation of osqueryi will allow the use of the ping table, such as:

osquery> select * from ping where url = "yahoo.com";  
osquery> select * from ping where url = "yahoo.com" or url = "8.8.8.8";  

[2]. The design choices mostly follow what existed and worked well.  

The code style and amount of logic follow that of the existing osquery curl table.  
(/osquery/tables/networking/curl.cpp)   
Input checking mainly relies on the existing infrastructure, such that
invalid input (URL value) is ignored.
Since a part of the server code is in C/C++, there is a potential of buffer overflow.
But the osquery infrastructure seems to be able to handle over 1M of URL length without crashing.

For the ping/ICMP logic, a number of existing ping programs have been referenced.
But the logic of Mike Muuss's program at https://gist.github.com/bugparty/ccba5744ba8f1cece5e0
has been modeled the most.
Using socket sendto() sending of the ICMP packet followed by select() to wait for the server reply
seems like a more comprehensive approach to handle all kinds of responses .
