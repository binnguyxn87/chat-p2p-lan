"""
Giao diện ứng dụng Chat P2P LAN - Tkinter (có sẵn trong Python).
- Bong bóng chat co giãn theo nội dung (nhúng widget thật, không tô màu cả dòng).
- Tính năng "xem dữ liệu mạng" ẩn trong menu Tuỳ chọn, không lộ liễu.
- Layout dùng grid + weight để co giãn đúng khi thay đổi kích thước cửa sổ.
"""
import sys
import os
import socket
import queue
import tkinter as tk
from tkinter import messagebox
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "network"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from peer import Peer
from discovery import Discovery
from crypto_bridge import CryptoBridge

BG_MAIN = "#0b1120"
BG_SIDEBAR = "#151d33"
BG_INPUT = "#1c2740"
ACCENT = "#6366f1"
ACCENT_DARK = "#4f46e5"
BUBBLE_ME = "#4f46e5"
BUBBLE_OTHER = "#233047"
TEXT_MAIN = "#e2e8f0"
TEXT_MUTED = "#64748b"
FONT_BASE = ("Segoe UI", 10)
FONT_BOLD = ("Segoe UI", 10, "bold")


def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip


def avatar_color(name):
    palette = ["#f87171", "#fb923c", "#fbbf24", "#4ade80", "#34d399",
               "#22d3ee", "#60a5fa", "#818cf8", "#c084fc", "#f472b6"]
    return palette[sum(ord(c) for c in name) % len(palette)]


class LoginWindow(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Chat P2P LAN")
        self.geometry("400x440")
        self.minsize(400, 440)
        self.configure(bg=BG_MAIN)

        wrap = tk.Frame(self, bg=BG_MAIN)
        wrap.place(relx=0.5, rely=0.5, anchor="center")

        tk.Label(wrap, text="🔐", font=("Segoe UI", 32), bg=BG_MAIN).pack(pady=(0, 4))
        tk.Label(wrap, text="CHAT P2P LAN", font=("Segoe UI", 19, "bold"),
                 bg=BG_MAIN, fg=ACCENT).pack(pady=(0, 2))
        tk.Label(wrap, text="Nhắn tin nội bộ, mã hóa đầu-cuối",
                 font=("Segoe UI", 9), bg=BG_MAIN, fg=TEXT_MUTED).pack(pady=(0, 26))

        form = tk.Frame(wrap, bg=BG_MAIN)
        form.pack()

        tk.Label(form, text="Tên hiển thị", bg=BG_MAIN, fg=TEXT_MUTED,
                 font=("Segoe UI", 9)).grid(row=0, column=0, sticky="w", pady=(0, 2))
        self.name_entry = tk.Entry(form, font=FONT_BASE, width=26, bg=BG_INPUT, fg="white",
                                    insertbackground="white", relief="flat", bd=8)
        self.name_entry.grid(row=1, column=0, pady=(0, 16), ipady=5)
        self.name_entry.insert(0, "Nguoi_dung")

        tk.Label(form, text="Cổng lắng nghe", bg=BG_MAIN, fg=TEXT_MUTED,
                 font=("Segoe UI", 9)).grid(row=2, column=0, sticky="w", pady=(0, 2))
        self.port_entry = tk.Entry(form, font=FONT_BASE, width=26, bg=BG_INPUT, fg="white",
                                    insertbackground="white", relief="flat", bd=8)
        self.port_entry.grid(row=3, column=0, pady=(0, 6), ipady=5)
        self.port_entry.insert(0, "5000")

        tk.Label(wrap, text=f"IP LAN của bạn: {get_local_ip()}", bg=BG_MAIN,
                 fg=TEXT_MUTED, font=("Segoe UI", 8)).pack(pady=(2, 0))

        btn = tk.Button(wrap, text="Vào phòng chat  ➤", font=FONT_BOLD,
                         bg=ACCENT, fg="white", activebackground=ACCENT_DARK,
                         activeforeground="white", relief="flat", padx=18, pady=10,
                         cursor="hand2", command=self._on_start)
        btn.pack(pady=(22, 0), fill="x")

        self.bind("<Return>", lambda e: self._on_start())
        self.name_entry.focus()

    def _on_start(self):
        name = self.name_entry.get().strip()
        port_str = self.port_entry.get().strip()
        if not name:
            messagebox.showerror("Lỗi", "Vui lòng nhập tên hiển thị.")
            return
        try:
            port = int(port_str)
            if not (1024 <= port <= 65535):
                raise ValueError
        except ValueError:
            messagebox.showerror("Lỗi", "Cổng phải là số từ 1024 đến 65535.")
            return

        try:
            self.destroy()
            app = ChatWindow(name, port)
            app.mainloop()
        except OSError as e:
            root = LoginWindow()
            messagebox.showerror("Lỗi", f"Không thể mở cổng {port}: {e}\nHãy thử cổng khác.")
            root.mainloop()


class PacketLogWindow(tk.Toplevel):
    def __init__(self, parent, history):
        super().__init__(parent)
        self.title("Dữ liệu mạng (nâng cao)")
        self.geometry("620x440")
        self.minsize(420, 300)
        self.configure(bg=BG_MAIN)

        tk.Label(self, text="Nội dung thực tế truyền qua socket mạng",
                 bg=BG_MAIN, fg=TEXT_MUTED, font=("Segoe UI", 9)).pack(anchor="w", padx=14, pady=(12, 8))

        self.log_area = tk.Text(self, bg="#060a14", fg="#94f0b0", font=("Consolas", 9),
                                 bd=0, highlightthickness=0, wrap="word", state="disabled",
                                 padx=12, pady=10)
        self.log_area.pack(fill="both", expand=True, padx=12, pady=(0, 12))
        self.log_area.tag_config("out", foreground="#60a5fa")
        self.log_area.tag_config("in", foreground="#4ade80")
        self.log_area.tag_config("meta", foreground=TEXT_MUTED)

        for entry in history:
            self.add_entry(*entry)

    def add_entry(self, direction, addr, raw):
        self.log_area.config(state="normal")
        ts = datetime.now().strftime("%H:%M:%S")
        tag = "out" if "OUT" in direction else "in"
        self.log_area.insert(tk.END, f"[{ts}] {direction}  {addr[0]}:{addr[1]}\n", tag)
        self.log_area.insert(tk.END, f"{raw}\n\n", "meta")
        self.log_area.config(state="disabled")
        self.log_area.see(tk.END)


def make_bubble(parent, sender, ts, content, is_me, warn=False):
    row = tk.Frame(parent, bg=BG_MAIN)

    bubble_bg = "#7f1d1d" if warn else (BUBBLE_ME if is_me else BUBBLE_OTHER)
    fg = "#fecaca" if warn else ("white" if is_me else TEXT_MAIN)

    col = tk.Frame(row, bg=BG_MAIN)
    col.pack(side="right" if is_me else "left", anchor="e" if is_me else "w")

    name_lbl = tk.Label(col, text=f"{sender}   {ts}", bg=BG_MAIN,
                         fg=("#c7d2fe" if is_me else ACCENT), font=("Segoe UI", 8, "bold"))
    name_lbl.pack(anchor="e" if is_me else "w", padx=4)

    bubble = tk.Label(col, text=content, bg=bubble_bg, fg=fg, font=FONT_BASE,
                       wraplength=380, justify="left", padx=12, pady=8)
    bubble.pack(anchor="e" if is_me else "w", pady=(2, 0))

    return row


class ChatWindow(tk.Tk):
    def __init__(self, my_name, my_port):
        super().__init__()
        self.my_name = my_name
        self.my_port = my_port
        self.selected_addr = None
        self.ui_queue = queue.Queue()
        self.packet_log_win = None
        self.wire_log_history = []

        self.title(f"Chat P2P LAN - {my_name}")
        self.geometry("920x620")
        self.minsize(700, 460)
        self.configure(bg=BG_MAIN)

        self._build_menu()
        self._build_ui()
        self._start_network()
        self.after(100, self._process_queue)
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _build_menu(self):
        menubar = tk.Menu(self)

        options_menu = tk.Menu(menubar, tearoff=0)
        options_menu.add_command(label="Xem dữ liệu mạng (nâng cao)", command=self._open_packet_log)
        menubar.add_cascade(label="Tuỳ chọn", menu=options_menu)

        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="Về ứng dụng", command=self._show_about)
        menubar.add_cascade(label="Trợ giúp", menu=help_menu)

        self.config(menu=menubar)

    def _show_about(self):
        messagebox.showinfo(
            "Về ứng dụng",
            "Chat P2P LAN\n\n"
            "Kết nối ngang hàng trong mạng nội bộ.\n"
            "Mã hóa đầu-cuối: RSA-2048 + AES-256-GCM + chữ ký số."
        )

    def _open_packet_log(self):
        if self.packet_log_win is None or not self.packet_log_win.winfo_exists():
            self.packet_log_win = PacketLogWindow(self, self.wire_log_history)
        else:
            self.packet_log_win.lift()
            self.packet_log_win.focus()

    def _build_ui(self):
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=0, minsize=230)
        self.grid_columnconfigure(1, weight=1)

        left = tk.Frame(self, bg=BG_SIDEBAR)
        left.grid(row=0, column=0, sticky="nsew")
        left.grid_rowconfigure(2, weight=1)
        left.grid_columnconfigure(0, weight=1)

        me_frame = tk.Frame(left, bg=BG_SIDEBAR)
        me_frame.grid(row=0, column=0, sticky="ew", padx=14, pady=(16, 10))
        tk.Label(me_frame, text="●", fg=avatar_color(self.my_name), bg=BG_SIDEBAR,
                 font=("Segoe UI", 13)).pack(side="left")
        tk.Label(me_frame, text=f" {self.my_name} (bạn)", bg=BG_SIDEBAR, fg="white",
                 font=("Segoe UI", 10, "bold")).pack(side="left")

        tk.Label(left, text="ĐANG HOẠT ĐỘNG", bg=BG_SIDEBAR, fg=TEXT_MUTED,
                 font=("Segoe UI", 8, "bold")).grid(row=1, column=0, sticky="w", padx=14, pady=(6, 4))

        list_wrap = tk.Frame(left, bg=BG_SIDEBAR)
        list_wrap.grid(row=2, column=0, sticky="nsew", padx=10)
        list_wrap.grid_rowconfigure(0, weight=1)
        list_wrap.grid_columnconfigure(0, weight=1)
        self.peer_listbox = tk.Listbox(list_wrap, bg=BG_MAIN, fg=TEXT_MAIN,
                                        selectbackground=ACCENT, selectforeground="white",
                                        font=("Segoe UI", 10), bd=0, highlightthickness=0,
                                        activestyle="none")
        self.peer_listbox.grid(row=0, column=0, sticky="nsew")
        self.peer_listbox.bind("<<ListboxSelect>>", self._on_select_peer)
        self._peer_addr_map = []

        tk.Label(left, text="Chọn 1 người để nhắn riêng, bỏ chọn để gửi cho tất cả.",
                 bg=BG_SIDEBAR, fg=TEXT_MUTED, font=("Segoe UI", 8), justify="left",
                 wraplength=200).grid(row=3, column=0, sticky="w", padx=14, pady=(8, 8))

        btn_clear = tk.Button(left, text="Bỏ chọn", font=("Segoe UI", 9, "bold"),
                               bg=BG_INPUT, fg=TEXT_MAIN, relief="flat", cursor="hand2",
                               activebackground=ACCENT, pady=6,
                               command=self._clear_selection)
        btn_clear.grid(row=4, column=0, sticky="ew", padx=10, pady=(0, 14))

        right = tk.Frame(self, bg=BG_MAIN)
        right.grid(row=0, column=1, sticky="nsew")
        right.grid_rowconfigure(0, weight=1)
        right.grid_columnconfigure(0, weight=1)

        canvas_wrap = tk.Frame(right, bg=BG_MAIN)
        canvas_wrap.grid(row=0, column=0, sticky="nsew")
        canvas_wrap.grid_rowconfigure(0, weight=1)
        canvas_wrap.grid_columnconfigure(0, weight=1)

        self.chat_canvas = tk.Canvas(canvas_wrap, bg=BG_MAIN, bd=0, highlightthickness=0)
        vsb = tk.Scrollbar(canvas_wrap, orient="vertical", command=self.chat_canvas.yview)
        self.chat_canvas.configure(yscrollcommand=vsb.set)
        self.chat_canvas.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")

        self.chat_inner = tk.Frame(self.chat_canvas, bg=BG_MAIN)
        self._chat_window_id = self.chat_canvas.create_window((0, 0), window=self.chat_inner,
                                                                anchor="nw")

        def _on_inner_configure(event):
            self.chat_canvas.configure(scrollregion=self.chat_canvas.bbox("all"))

        def _on_canvas_configure(event):
            self.chat_canvas.itemconfig(self._chat_window_id, width=event.width)

        self.chat_inner.bind("<Configure>", _on_inner_configure)
        self.chat_canvas.bind("<Configure>", _on_canvas_configure)

        def _on_mousewheel(event):
            self.chat_canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

        self.chat_canvas.bind_all("<MouseWheel>", _on_mousewheel)

        inputbar = tk.Frame(right, bg=BG_SIDEBAR, height=60)
        inputbar.grid(row=1, column=0, sticky="ew")
        inputbar.grid_propagate(False)
        inputbar.grid_columnconfigure(0, weight=1)

        self.msg_entry = tk.Entry(inputbar, font=FONT_BASE, bg=BG_INPUT, fg="white",
                                   insertbackground="white", relief="flat")
        self.msg_entry.grid(row=0, column=0, sticky="ew", padx=(14, 8), pady=12, ipady=7)
        self.msg_entry.bind("<Return>", lambda e: self._on_send())

        send_btn = tk.Button(inputbar, text="Gửi  ➤", font=FONT_BOLD,
                              bg=ACCENT, fg="white", activebackground=ACCENT_DARK,
                              activeforeground="white", relief="flat", cursor="hand2",
                              padx=18, command=self._on_send)
        send_btn.grid(row=0, column=1, padx=(0, 14), pady=12)

    def _start_network(self):
        self.peer = Peer(self.my_name, self.my_port)
        self.bridge = CryptoBridge(self.peer)

        self.peer.on_message_received = self._net_on_message
        orig_connected = self.peer.on_peer_connected
        orig_disconnected = self.peer.on_peer_disconnected

        def on_connected(addr, initiator):
            orig_connected(addr, initiator)
            self.ui_queue.put(("peer_list_update", None))

        def on_disconnected(addr):
            orig_disconnected(addr)
            self.ui_queue.put(("peer_list_update", None))
            self.ui_queue.put(("system", f"{self.bridge.get_display_name(addr)} đã rời khỏi phòng chat"))

        self.peer.on_peer_connected = on_connected
        self.peer.on_peer_disconnected = on_disconnected

        def on_status_change(addr, status):
            self.ui_queue.put(("peer_list_update", None))
            if status.startswith("Đã mã hóa"):
                self.ui_queue.put(("system", f"{self.bridge.get_display_name(addr)} đã tham gia phòng chat"))

        self.bridge.on_status_change = on_status_change
        self.bridge.on_wire_log = lambda direction, addr, raw: self.ui_queue.put(("wire_log", (direction, addr, raw)))

        import threading
        threading.Thread(target=self.peer.start_listening, daemon=True).start()

        def on_peer_found(name, ip, port):
            self.peer.connect_to(ip, port)

        self.discovery = Discovery(self.my_name, self.my_port, on_peer_found)
        self.discovery.start()

    def _net_on_message(self, sender, content, addr):
        self.ui_queue.put(("message", (sender, content, addr)))

    def _process_queue(self):
        try:
            while True:
                kind, data = self.ui_queue.get_nowait()
                if kind == "message":
                    sender, content, addr = data
                    self._append_chat(sender, content, is_me=False)
                elif kind == "system":
                    self._append_system(data)
                elif kind == "peer_list_update":
                    self._refresh_peer_list()
                elif kind == "wire_log":
                    direction, addr, raw = data
                    self.wire_log_history.append((direction, addr, raw))
                    if self.packet_log_win is not None and self.packet_log_win.winfo_exists():
                        self.packet_log_win.add_entry(direction, addr, raw)
        except queue.Empty:
            pass
        self.after(150, self._process_queue)

    def _refresh_peer_list(self):
        self.peer_listbox.delete(0, tk.END)
        self._peer_addr_map = []
        for addr in self.peer.list_peers():
            ready = self.bridge.is_ready(addr)
            status = "🔒" if ready else "⏳"
            name = self.bridge.get_display_name(addr)
            self.peer_listbox.insert(tk.END, f"{status}  {name}")
            self._peer_addr_map.append(addr)

    def _on_select_peer(self, event):
        sel = self.peer_listbox.curselection()
        if sel:
            self.selected_addr = self._peer_addr_map[sel[0]]
        else:
            self.selected_addr = None

    def _clear_selection(self):
        self.peer_listbox.selection_clear(0, tk.END)
        self.selected_addr = None

    def _on_send(self):
        text = self.msg_entry.get().strip()
        if not text:
            return
        self.msg_entry.delete(0, tk.END)

        if self.selected_addr and self.selected_addr in self.peer.connections:
            self.peer.send_message(self.selected_addr, text)
        else:
            if not self.peer.list_peers():
                self._append_system("Chưa có ai trong phòng chat.")
                return
            self.peer.broadcast(text)

        self._append_chat(self.my_name, text, is_me=True)

    def _append_chat(self, sender, content, is_me):
        ts = datetime.now().strftime("%H:%M")
        warn = content.startswith("[CẢNH BÁO]") or content.startswith("[LỖI")
        bubble_row = make_bubble(self.chat_inner, sender, ts, content, is_me, warn=warn)
        bubble_row.pack(fill="x", padx=14, pady=4)
        self.after(20, self._scroll_to_bottom)

    def _append_system(self, text):
        row = tk.Frame(self.chat_inner, bg=BG_MAIN)
        tk.Label(row, text=text, bg=BG_MAIN, fg=TEXT_MUTED,
                 font=("Segoe UI", 8, "italic")).pack()
        row.pack(fill="x", pady=6)
        self.after(20, self._scroll_to_bottom)

    def _scroll_to_bottom(self):
        self.chat_canvas.update_idletasks()
        self.chat_canvas.yview_moveto(1.0)

    def _on_close(self):
        try:
            self.discovery.stop()
            self.peer.shutdown()
        except Exception:
            pass
        self.destroy()


if __name__ == "__main__":
    login = LoginWindow()
    login.mainloop()
