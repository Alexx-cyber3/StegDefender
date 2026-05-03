import argparse
import sys
import os
from colorama import init, Fore, Style
from stegdefender.core.engine import ForensicEngine

init(autoreset=True)

def print_header():
    print(Fore.CYAN + "=" * 50)
    print(Fore.CYAN + "      STEGDEFENDER - RECURSIVE FORENSIC ENGINE")
    print(Fore.CYAN + "=" * 50)

def print_node(node, indent=0):
    spacing = "  " * indent
    filename = node['filename']
    results = node['findings']
    file_info = node['info']
    
    print(f"{spacing}{Fore.YELLOW}Target: {filename} ({file_info['mime']})")
    
    verdict_color = Fore.GREEN
    if results['verdict'] == 'Suspicious':
        verdict_color = Fore.YELLOW
    elif results['verdict'] == 'Stego Detected':
        verdict_color = Fore.RED
        
    print(f"{spacing}Verdict: {verdict_color}{results['verdict']}{Style.RESET_ALL}")
    
    if 'metadata' in results and results['metadata']:
        print(f"{spacing}{Fore.BLUE}[METADATA]{Style.RESET_ALL}")
        for k, v in results['metadata'].items():
            print(f"{spacing}  {k}: {v}")

    for detail in results['details']:
        prefix = "[INFO]"
        color = Fore.WHITE
        if detail['severity'] == 'warning':
            prefix = "[WARN]"
            color = Fore.YELLOW
        elif detail['severity'] == 'danger':
            prefix = "[ALERT]"
            color = Fore.RED
        print(f"{spacing}{color}{prefix} {detail['message']}")
    
    for nest in node['nested']:
        print(f"\n{spacing}{Fore.CYAN}--- ENTERING NESTED ARTIFACT: {nest['artifact_name']} ---")
        print_node(nest['analysis'], indent + 2)

def main():
    parser = argparse.ArgumentParser(description="StegDefender - Recursive Forensic Engine")
    parser.add_argument("file", help="Path to the file to analyze")
    parser.add_argument("--depth", type=int, default=3, help="Max recursion depth")
    args = parser.parse_args()
    
    print_header()
    
    if not os.path.exists(args.file):
        print(Fore.RED + f"Error: File '{args.file}' not found.")
        sys.exit(1)
        
    engine = ForensicEngine(max_depth=args.depth)
    results_tree = engine.run(args.file)
    
    print(f"\n{Fore.CYAN}--- FINAL FORENSIC TREE ---")
    print_node(results_tree)

if __name__ == "__main__":
    main()