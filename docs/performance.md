# Performance
This section describes the results of the performance tests.

## TCP
I used the curl -w option(time_total) to connect to the wordpress web site 10000 times and measured the results.

| (unit: ms) | no-system | furui  |
|------------|-----------|------------|
| mean       | 43.550882 | 46.750199  |
| min        | 39.429000 | 41.049000  |
| max        | 93.811000 | 125.974000 |

## ICMP
I used the ping to connect to the container from host 50 times and measured the results.



| (unit: ms) | no-system | furui  |
|------------|-----------|------------|
| mean       | 0.148     | 0.238      |


