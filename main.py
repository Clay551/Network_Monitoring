import os
import time
import socket
import platform
import subprocess
import psutil
import requests
import json
import logging
from datetime import datetime
from threading import Thread

logging.basicConfig(
    filename='network_monitor.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class AdvancedNetworkMonitor:
    def __init__(self):
        self.websites = [
            "google.com",
            "github.com",
            "stackoverflow.com",
            "wikipedia.org",
            "yahoo.com"
        ]
        self.ping_threshold = 100
        self.packet_loss_threshold = 5
        self.history = []
        self.alert_count = 0
        
        os.makedirs('network_data', exist_ok=True)
    
    def get_network_interfaces(self):
        interfaces_info = []
        
        for interface, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == socket.AF_INET:
                    interfaces_info.append({
                        "interface": interface,
                        "ip": addr.address,
                        "netmask": addr.netmask,
                        "broadcast": addr.broadcast
                    })
        
        return interfaces_info
    
    def get_network_stats(self):
        stats = psutil.net_io_counters()
        return {
            "bytes_sent": stats.bytes_sent,
            "bytes_recv": stats.bytes_recv,
            "packets_sent": stats.packets_sent,
            "packets_recv": stats.packets_recv,
            "errin": stats.errin,
            "errout": stats.errout,
            "dropin": stats.dropin,
            "dropout": stats.dropout
        }
    
    def ping_host(self, host, count=4):
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        command = ['ping', param, str(count), host]
        
        try:
            output = subprocess.check_output(command).decode('utf-8')
            
            if platform.system().lower() == 'windows':
                avg_ping = float(output.split('Average = ')[1].split('ms')[0].strip())
            else:
                avg_ping = float(output.split('rtt min/avg/max/mdev = ')[1].split('/')[1])
            
            if platform.system().lower() == 'windows':
                packet_loss = int(output.split('(')[1].split('%')[0])
            else:
                packet_loss = int(output.split('received, ')[1].split('%')[0])
            
            return {
                "success": True,
                "avg_ping": avg_ping,
                "packet_loss": packet_loss,
                "raw_output": output
            }
        except Exception as e:
            logging.error(f"Error pinging {host}: {str(e)}")
            return {
                "success": False,
                "error": str(e)
            }
    
    def check_website_status(self, website):
        try:
            start_time = time.time()
            response = requests.get(f"http://{website}", timeout=5)
            response_time = (time.time() - start_time) * 1000
            
            return {
                "status": response.status_code,
                "response_time": response_time,
                "accessible": True,
                "headers": dict(response.headers)
            }
        except requests.RequestException as e:
            logging.error(f"Error accessing {website}: {str(e)}")
            return {
                "status": None,
                "response_time": None,
                "accessible": False,
                "error": str(e)
            }
    
    def trace_route(self, host):
        command = ['tracert' if platform.system().lower() == 'windows' else 'traceroute', host]
        
        try:
            output = subprocess.check_output(command, timeout=20).decode('utf-8')
            return {
                "success": True,
                "output": output
            }
        except Exception as e:
            logging.error(f"Error running traceroute for {host}: {str(e)}")
            return {
                "success": False,
                "error": str(e)
            }
    
    def check_dns(self, domain):
        try:
            ip = socket.gethostbyname(domain)
            return {
                "success": True,
                "ip": ip
            }
        except socket.gaierror as e:
            logging.error(f"Error in DNS lookup for {domain}: {str(e)}")
            return {
                "success": False,
                "error": str(e)
            }
    
    def analyze_network_health(self, ping_result):
        if not ping_result["success"]:
            return {
                "status": "critical",
                "message": "Internet is not accessible"
            }
        
        if ping_result["packet_loss"] > self.packet_loss_threshold:
            return {
                "status": "warning",
                "message": f"Packet loss: {ping_result['packet_loss']}%"
            }
        
        if ping_result["avg_ping"] > self.ping_threshold:
            return {
                "status": "warning",
                "message": f"High latency: {ping_result['avg_ping']} ms"
            }
        
        return {
            "status": "good",
            "message": "Network is healthy"
        }
    
    def collect_data(self):
        timestamp = datetime.now().isoformat()
        
        interfaces = self.get_network_interfaces()
        
        network_stats = self.get_network_stats()
        
        ping_result = self.ping_host("8.8.8.8")
        
        websites_status = {}
        for website in self.websites:
            websites_status[website] = self.check_website_status(website)
        
        health_analysis = self.analyze_network_health(ping_result)
        
        data = {
            "timestamp": timestamp,
            "interfaces": interfaces,
            "network_stats": network_stats,
            "ping_result": ping_result,
            "websites_status": websites_status,
            "health_analysis": health_analysis
        }
        
        self.history.append(data)
        
        if len(self.history) > 100:
            self.history.pop(0)
        
        with open(f'network_data/network_data_{datetime.now().strftime("%Y%m%d")}.json', 'a') as f:
            f.write(json.dumps(data) + '\n')
        
        if health_analysis["status"] != "good":
            self.alert_count += 1
            logging.warning(f"Network alert: {health_analysis['message']}")
            
            if self.alert_count >= 3:
                self.diagnose_network_issues()
        else:
            self.alert_count = 0
        
        return data
    
    def diagnose_network_issues(self):
        logging.info("Diagnosing network issues...")
        
        dns_result = self.check_dns("google.com")
        if not dns_result["success"]:
            logging.error("DNS problem: Unable to resolve domain name")
        
        trace_result = self.trace_route("8.8.8.8")
        if not trace_result["success"]:
            logging.error("Network routing problem")
        else:
            logging.info("Traceroute result saved")
            with open(f'network_data/traceroute_{datetime.now().strftime("%Y%m%d_%H%M%S")}.txt', 'w') as f:
                f.write(trace_result["output"])
        
        interfaces = self.get_network_interfaces()
        if not interfaces:
            logging.error("No network card found with IP address")
        
        stats = self.get_network_stats()
        if stats["errin"] > 0 or stats["errout"] > 0:
            logging.error(f"Network errors: Input={stats['errin']}, Output={stats['errout']}")
        
        if stats["dropin"] > 0 or stats["dropout"] > 0:
            logging.error(f"Lost packets: Input={stats['dropin']}, Output={stats['dropout']}")
    
    def display_text_info(self, data):
        os.system('cls' if platform.system().lower() == 'windows' else 'clear')
        
        print("=" * 60)
        print(f"Advanced Network Monitoring - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 60)
        
        health = data["health_analysis"]
        health_status = {
            "good": "🟢 Good",
            "warning": "🟡 Warning",
            "critical": "🔴 Critical"
        }
        
        print(f"\nNetwork status: {health_status.get(health['status'], health['status'])}")
        print(f"Message: {health['message']}")
        
        print("\nNetwork card information:")
        print("-" * 60)
        for interface in data["interfaces"]:
            print(f"Network card: {interface['interface']}")
            print(f"IP address: {interface['ip']}")
            print(f"Netmask: {interface['netmask']}")
            print(f"Broadcast: {interface['broadcast']}")
            print("-" * 30)
        
        stats = data["network_stats"]
        print("\nNetwork traffic statistics:")
        print("-" * 60)
        print(f"Bytes sent: {stats['bytes_sent'] / (1024*1024):.2f} MB")
        print(f"Bytes received: {stats['bytes_recv'] / (1024*1024):.2f} MB")
        print(f"Packets sent: {stats['packets_sent']}")
        print(f"Packets received: {stats['packets_recv']}")
        print(f"Input errors: {stats['errin']}")
        print(f"Output errors: {stats['errout']}")
        print(f"Lost input packets: {stats['dropin']}")
        print(f"Lost output packets: {stats['dropout']}")
        
        ping = data["ping_result"]
        print("\nPing results to 8.8.8.8:")
        print("-" * 60)
        if ping["success"]:
            print(f"Average ping: {ping['avg_ping']:.2f} ms")
            print(f"Packet loss: {ping['packet_loss']}%")
        else:
            print(f"Ping failed: {ping.get('error', 'Unknown error')}")
        
        print("\nWebsite status:")
        print("-" * 60)
        for website, status in data["websites_status"].items():
            if status["accessible"]:
                print(f"{website}: Accessible (Code {status['status']}, Response time: {status['response_time']:.2f} ms)")
            else:
                print(f"{website}: Not accessible ({status.get('error', 'Unknown error')})")
        
        print("\nData is saved in the 'network_data' folder.")
        print("Logs are saved in the 'network_monitor.log' file.")
        print("\nMonitoring... (Press Ctrl+C to exit)")
    
    def generate_report(self):
        if not self.history:
            return "No data available for reporting."
        
        report = []
        report.append("=" * 80)
        report.append(f"Network Monitoring Report - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append("=" * 80)
        report.append("")
        
        avg_pings = []
        for data in self.history:
            if data["ping_result"]["success"]:
                avg_pings.append(data["ping_result"]["avg_ping"])
        
        if avg_pings:
            avg_ping = sum(avg_pings) / len(avg_pings)
            min_ping = min(avg_pings)
            max_ping = max(avg_pings)
            report.append(f"Average ping: {avg_ping:.2f} ms (Minimum: {min_ping:.2f} ms, Maximum: {max_ping:.2f} ms)")
        
        website_access = {}
        for website in self.websites:
            access_count = 0
            for data in self.history:
                if data["websites_status"][website]["accessible"]:
                    access_count += 1
            
            if self.history:
                access_percentage = (access_count / len(self.history)) * 100
                website_access[website] = access_percentage
        
        report.append("\nWebsite access percentage:")
        for website, percentage in website_access.items():
            report.append(f"{website}: {percentage:.2f}%")
        
        health_counts = {"good": 0, "warning": 0, "critical": 0}
        for data in self.history:
            status = data["health_analysis"]["status"]
            health_counts[status] = health_counts.get(status, 0) + 1
        
        report.append("\nNetwork health status:")
        for status, count in health_counts.items():
            if self.history:
                percentage = (count / len(self.history)) * 100
                report.append(f"{status}: {count} ({percentage:.2f}%)")
        
        report_text = "\n".join(report)
        report_file = f'network_data/report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.txt'
        
        with open(report_file, 'w') as f:
            f.write(report_text)
        
        return report_text
    
    def run(self):
        try:
            logging.info("Starting network monitoring")
            print("Starting network monitoring...")
            
            while True:
                data = self.collect_data()
                
                self.display_text_info(data)
                
                current_time = datetime.now()
                if current_time.minute == 0 and current_time.second < 10:
                    report = self.generate_report()
                    logging.info("Hourly report generated")
                
                time.sleep(10)
                
        except KeyboardInterrupt:
            print("\nMonitoring stopped.")
            logging.info("Network monitoring stopped")
            
            print("\nGenerating final report...")
            report = self.generate_report()
            print(f"Final report saved to file.")
            print("Exiting program.")

if __name__ == "__main__":
    monitor = AdvancedNetworkMonitor()
    monitor.run()
