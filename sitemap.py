import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog
import logging
from urllib.parse import urljoin, urlparse
import requests
from bs4 import BeautifulSoup
from PIL import Image, ImageTk
import threading
import time

logging.basicConfig(
    format='%(asctime)s %(levelname)s:%(message)s',
    level=logging.INFO)

class CrawlerGUI:

    def __init__(self):
        self.visited_urls = set()
        self.urls_to_visit = []
        self.stop_crawling = False

        self.root = tk.Tk()
        self.root.title("Web Crawler")

        # Frame for the left side (crawling)
        self.crawling_frame = tk.Frame(self.root)
        self.crawling_frame.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")

        # Treeview to display the organized sitemap
        self.sitemap_tree = ttk.Treeview(self.crawling_frame, columns=("Status"), show="tree")
        self.sitemap_tree.heading("#0", text="Sitemap")
        self.sitemap_tree.heading("Status", text="Status")
        self.sitemap_tree.column("Status", width=100, anchor="center")
        self.sitemap_tree.pack(fill=tk.BOTH, expand=True)  # Make Treeview resizable

        # Frame for the top center (URL entry)
        self.url_frame = tk.Frame(self.root)
        self.url_frame.grid(row=0, column=1, padx=10, pady=10, sticky="nsew")

        # Entry widget for user input
        self.entry_label = tk.Label(self.url_frame, text="Enter starting URL:")
        self.entry_label.grid(row=0, column=0, pady=5)

        self.entry = tk.Entry(self.url_frame, width=40)
        self.entry.grid(row=1, column=0, pady=5, padx=5)

        # Frame for the right side (crawling)
        self.right_frame = tk.Frame(self.root)
        self.right_frame.grid(row=0, column=2, padx=10, pady=10, sticky="nsew")

        # Frame for crawling
        self.crawling_subframe = tk.Frame(self.right_frame)
        self.crawling_subframe.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")

        # Button to start crawling
        self.crawl_button = tk.Button(self.crawling_subframe, text="Start Crawling", command=self.start_crawling_thread)
        self.crawl_button.grid(row=0, column=0, pady=10)

        # Button to stop crawling
        self.stop_button = tk.Button(self.crawling_subframe, text="Stop Crawling", command=self.stop_crawling)
        self.stop_button.grid(row=1, column=0, pady=10)

        # Entry for crawling time limit
        self.time_label = tk.Label(self.crawling_subframe, text="Crawling Time Limit (minutes):")
        self.time_label.grid(row=2, column=0, pady=5)

        self.time_entry = tk.Entry(self.crawling_subframe, width=10)
        self.time_entry.grid(row=3, column=0, pady=5, padx=5)

        # Progress bar for crawling
        self.crawling_progress_var = tk.DoubleVar()
        self.crawling_progress = ttk.Progressbar(self.crawling_subframe, orient="horizontal", length=200, mode="determinate", variable=self.crawling_progress_var)
        self.crawling_progress.grid(row=4, column=0, pady=10)

        # ScrolledText widget to display the Crawling output
        self.crawling_output_label = tk.Label(self.crawling_subframe, text="Crawling Output:")
        self.crawling_output_label.grid(row=5, column=0, pady=5)

        self.crawling_output = scrolledtext.ScrolledText(self.crawling_subframe, width=40, height=15)
        self.crawling_output.grid(row=6, column=0, pady=5)

        # Load icons
        self.domain_icon_path = "domain_icon.png"
        self.folder_icon_path = "folder_icon.png"
        self.file_icon_path = "file_icon.png"

        # Check if the icons exist, otherwise, set them to None
        try:
            self.domain_icon = ImageTk.PhotoImage(Image.open(self.domain_icon_path).resize((16, 16)))
            self.folder_icon = ImageTk.PhotoImage(Image.open(self.folder_icon_path).resize((16, 16)))
            self.file_icon = ImageTk.PhotoImage(Image.open(self.file_icon_path).resize((16, 16)))
        except Exception as e:
            logging.error(f"Failed to load icons: {str(e)}")
            self.domain_icon = None
            self.folder_icon = None
            self.file_icon = None

        # File menu
        self.menu_bar = tk.Menu(self.root)
        self.root.config(menu=self.menu_bar)
        self.file_menu = tk.Menu(self.menu_bar, tearoff=0)
        self.menu_bar.add_cascade(label="File", menu=self.file_menu)
        self.file_menu.add_command(label="Save Sitemap", command=self.save_sitemap)

        # Add threading lock
        self.lock = threading.Lock()

        # Add a flag to indicate if the crawling process is in progress
        self.crawling_in_progress = False

    def on_close(self):
        self.stop_crawling = True
        self.root.destroy()

    def extract_domain_and_path(self, url):
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        path = parsed_url.path
        if not path:
            path = "/"
        return domain, path

    def add_url_to_visit(self, url):
        domain, path = self.extract_domain_and_path(url)
        if url not in self.visited_urls:
            self.visited_urls.add(url)

            # Check if the domain node already exists
            domain_node = self.find_treeview_item(domain)
            if domain_node is None:
                domain_node = self.sitemap_tree.insert("", "end", text=domain, image=self.domain_icon)

            # Add the path under the domain
            folders = path.split("/")
            current_node = domain_node
            for folder in folders:
                if folder:
                    folder_item = self.find_treeview_item_in_children(current_node, folder)
                    if folder_item is None:
                        folder_item = self.sitemap_tree.insert(current_node, "end", text=folder, image=self.folder_icon)
                    current_node = folder_item

            # Add the URL under the last folder
            self.sitemap_tree.insert(current_node, "end", text=url, image=self.file_icon)

    def find_treeview_item(self, item_text):
        for item in self.sitemap_tree.get_children():
            if self.sitemap_tree.item(item, "text") == item_text:
                return item
        return None

    def find_treeview_item_in_children(self, parent, item_text):
        for item in self.sitemap_tree.get_children(parent):
            if self.sitemap_tree.item(item, "text") == item_text:
                return item
        return None

    def update_progress_by_time(self):
        if self.crawling_time_limit is not None:
            elapsed_time = time.time() - self.start_time
            progress = (elapsed_time / (self.crawling_time_limit * 60)) * 100
            self.crawling_progress_var.set(progress)
            if elapsed_time >= self.crawling_time_limit * 60:
                logging.info(f"Crawling time limit reached. Stopping crawling.")
                self.stop_crawling()

    def start_crawling_thread(self):
        threading.Thread(target=self.start_crawling).start()

    def start_crawling(self):
        self.crawling_output.delete(1.0, tk.END)
        self.visited_urls = set()
        self.urls_to_visit = [self.entry.get()]
        self.stop_crawling = False
        self.crawling_in_progress = True  # Set the flag to indicate crawling is in progress
        self.crawling_progress_var.set(0)
        self.start_time = time.time()

        # Get crawling time limit from user input
        try:
            self.crawling_time_limit = float(self.time_entry.get())
        except ValueError:
            logging.error("Invalid time limit. Crawling will continue until manually stopped.")
            self.crawling_time_limit = None

        while not self.stop_crawling:
            url = self.get_next_url_to_crawl()
            if not url:
                break

            self.add_url_to_visit(url)
            try:
                self.crawl(url)
            except Exception as e:
                logging.error(f"Failed to crawl: {url}\n{str(e)}")

            self.update_progress_by_time()

            # Add a short sleep duration for better responsiveness
            time.sleep(0.01)

        self.crawling_in_progress = False  # Set the flag to indicate crawling is complete

        if not self.stop_crawling:
            logging.info("Crawling completed.")

    def get_next_url_to_crawl(self):
        if self.urls_to_visit:
            return self.urls_to_visit.pop(0)
        else:
            return None

    def crawl(self, url):
        html = self.download_url(url)
        soup = BeautifulSoup(html, "html.parser")

        # Extract links from the page
        links = soup.find_all("a", href=True)
        for link in links:
            new_url = urljoin(url, link["href"])
            if new_url not in self.visited_urls and new_url not in self.urls_to_visit:
                self.urls_to_visit.append(new_url)

    def download_url(self, url):
        # Set user-agent header
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'}
        
        with self.lock:
            return requests.get(url, headers=headers, verify=False).text

    def stop_crawling(self):
        self.stop_crawling = True
        while self.crawling_in_progress:
            self.root.update()  # Force update the main loop
        time.sleep(0.01)  # Add a short sleep duration for better responsiveness
        logging.info("Crawling stopped.")

    def save_sitemap(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if file_path:
            with open(file_path, "w") as file:
                file.write("Site Map:\n\n")
                for url in self.visited_urls:
                    file.write(f"{url}\n")
                logging.info(f"Site map saved to {file_path}")

    def run(self):
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.root.mainloop()

# Example usage
if __name__ == "__main__":
    crawler_gui = CrawlerGUI()
    crawler_gui.run()
