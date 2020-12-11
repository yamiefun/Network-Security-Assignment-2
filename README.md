# Network Security Assignment 2
The purpose of this project is to analyze the system logs and determined what kind of attack it’s under.
[Assignment Spec](https://github.com/dsnslab/NetworkSecurity/blob/master/109-1/Project2/NS_Project2_spec.pdf)

[Data](https://drive.google.com/file/d/1X-witM-MUXhk5iQmLTP6Xdf6KJnOh7qA/view?fbclid=IwAR3syCEsR7iw5AViwTpfzc2FKYeEQKZnl5QLJcomlKGl1mk6fodh2sFvSNw)

## Files
+ `hw2.py`: The main code of this assignment.
+ `calculate.py`: Code that can analyze the logs to find the ratio of some special logs when the server is under specific attack.

## How to Run
Just simply run the command in terminal.
```
python3 hw2.py [path to log]
```
For example,
```
python3 hw2.py ./Logs/Example_Test
```
Please make sure that the directory structure should be the same as the explaination in [Assignment Spec](https://github.com/dsnslab/NetworkSecurity/blob/master/109-1/Project2/NS_Project2_spec.pdf).

## Sample Output
![](https://i.imgur.com/zdf16wr.png)