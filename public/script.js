const API = "";
let token = localStorage.getItem("token");
let user = JSON.parse(localStorage.getItem("user") || "null");

function showSection(id) {
  document.querySelectorAll(".section").forEach((s) => s.classList.remove("active"));
  const section = document.getElementById("section-" + id);
  if (section) section.classList.add("active");
  window.scrollTo({ top: 0, behavior: "smooth" });
  updateNav();
  if (id === "booking") updateBookingAuth();
}

function updateNav() {
  const navLinks = document.getElementById("navLinks");
  const navUser = document.getElementById("navUser");

  let links = '<a onclick="showSection(\'home\')">Home</a>';

  if (!user) {
    links += '<a onclick="showSection(\'userLogin\')">Sign In</a>';
    links += '<a onclick="showSection(\'booking\')">Book a Table</a>';

    navUser.innerHTML = "";
  } else {
    links += '<a onclick="showSection(\'booking\')">Book a Table</a>';

    navUser.innerHTML = `<span style="color:#c9a96e;font-weight:600;">${user.name}</span> (${user.role}) <a onclick="logout()" style="color:#e74c3c;cursor:pointer;margin-left:8px;">Logout</a>`;
  }

  navLinks.innerHTML = links;
}

async function logout() {
  try { await fetch("/api/logout", { method: "POST", headers: { Authorization: "Bearer " + token } }); } catch {}
  localStorage.removeItem("token");
  localStorage.removeItem("user");
  token = null;
  user = null;
  updateNav();
  showSection("home");
}

function showMsg(elId, text, type) {
  const el = document.getElementById(elId);
  el.textContent = text;
  el.className = "msg " + type;
}

function clearMsg(elId) {
  const el = document.getElementById(elId);
  el.textContent = "";
  el.className = "msg";
}

// ─── USER LOGIN ───
document.getElementById("userLoginForm")?.addEventListener("submit", async (e) => {
  e.preventDefault();
  clearMsg("userLoginMsg");
  const email = document.getElementById("userLoginEmail").value;
  const password = document.getElementById("userLoginPassword").value;
  try {
    const res = await fetch(API + "/api/users/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password }),
    });
    const data = await res.json();
    if (!res.ok) return showMsg("userLoginMsg", data.error, "error");
    token = data.token;
    user = data.user;
    localStorage.setItem("token", token);
    localStorage.setItem("user", JSON.stringify(user));
    updateNav();
    showSection("booking");
  } catch {
    showMsg("userLoginMsg", "Connection error", "error");
  }
});

// ─── USER REGISTER ───
document.getElementById("userRegisterForm")?.addEventListener("submit", async (e) => {
  e.preventDefault();
  clearMsg("userRegMsg");
  const name = document.getElementById("userRegName").value;
  const email = document.getElementById("userRegEmail").value;
  const phone = document.getElementById("userRegPhone").value;
  const password = document.getElementById("userRegPassword").value;
  try {
    const res = await fetch(API + "/api/users/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name, email, password, phone }),
    });
    const data = await res.json();
    if (!res.ok) return showMsg("userRegMsg", data.error, "error");
    token = data.token;
    user = data.user;
    localStorage.setItem("token", token);
    localStorage.setItem("user", JSON.stringify(user));
    updateNav();
    showSection("booking");
  } catch {
    showMsg("userRegMsg", "Connection error", "error");
  }
});

// ─── AUTH TAB SWITCHING ───
function switchAuthTab(tab) {
  document.querySelectorAll(".auth-tab").forEach((t) => t.classList.remove("active"));
  if (tab === "login") {
    document.querySelector(".auth-tab:nth-child(1)").classList.add("active");
    document.getElementById("authLoginForm").style.display = "block";
    document.getElementById("authRegisterForm").style.display = "none";
  } else {
    document.querySelector(".auth-tab:nth-child(2)").classList.add("active");
    document.getElementById("authLoginForm").style.display = "none";
    document.getElementById("authRegisterForm").style.display = "block";
  }
}

// ─── BOOKING ───
document.addEventListener("DOMContentLoaded", async () => {
  try {
    const res = await fetch("/api/auth/me");
    const data = await res.json();
    if (data.user && data.token) {
      token = data.token;
      user = data.user;
      localStorage.setItem("token", token);
      localStorage.setItem("user", JSON.stringify(user));
    } else {
      localStorage.removeItem("token");
      localStorage.removeItem("user");
      token = null;
      user = null;
    }
  } catch {
    localStorage.removeItem("token");
    localStorage.removeItem("user");
    token = null;
    user = null;
  }
  updateNav();
  const today = new Date().toISOString().split("T")[0];
  const dateInput = document.getElementById("bookingDate");
  if (dateInput) {
    dateInput.value = today;
    dateInput.min = today;
  }
  updateBookingAuth();
});

function updateBookingAuth() {
  const authMsg = document.getElementById("bookingAuthMsg");
  const content = document.getElementById("bookingContent");
  if (user && user.role === "user") {
    authMsg.style.display = "none";
    content.style.display = "block";
    loadMyBookings();
    checkAvailability();
  } else {
    authMsg.style.display = "block";
    content.style.display = "none";
  }
}

let selectedTableId = null;

async function checkAvailability() {
  const date = document.getElementById("bookingDate").value;
  const time = document.getElementById("bookingTime").value;
  const guests = document.getElementById("bookingGuests").value;

  if (!date) return alert("Please select a date");

  clearMsg("bookingMsg");
  selectedTableId = null;
  document.getElementById("selectedTableInfo").textContent = "";
  document.getElementById("confirmBookingBtn").style.display = "none";
  document.getElementById("seatMap").innerHTML = '<div style="grid-column:1/-1;display:flex;align-items:center;justify-content:center;color:#a0a0b0;min-height:200px;"><span>Loading available tables...</span></div>';

  try {
    const res = await fetch(API + `/api/tables/available?date=${date}&time=${time}&guests=${guests}`);
    const data = await res.json();
    renderSeatMap(data);
  } catch {
    showMsg("bookingMsg", "Error loading availability", "error");
  }
}

function renderSeatMap(data) {
  const map = document.getElementById("seatMap");
  map.innerHTML = "";

  const allTables = data.all || [];
  const availableIds = (data.available || []).map((t) => t.id);
  const bookedIds = (data.booked || []).map((t) => t.id);

  allTables.forEach((table) => {
    const cell = document.createElement("div");
    cell.className = "table-cell";
    cell.dataset.tableId = table.id;

    if (availableIds.includes(table.id)) {
      cell.classList.add("available");
      cell.innerHTML = `${table.label}<span class="capacity-badge">${table.capacity}p</span>`;
      cell.onclick = () => selectTable(table.id);
    } else {
      cell.classList.add("booked");
      cell.innerHTML = `${table.label}<span class="capacity-badge">${table.capacity}p</span>`;
    }
    map.appendChild(cell);
  });
}

function selectTable(tableId) {
  document.querySelectorAll(".table-cell").forEach((c) => c.classList.remove("selected"));
  const cell = document.querySelector(`.table-cell[data-table-id="${tableId}"]`);
  if (!cell) return;
  cell.classList.add("selected");
  selectedTableId = tableId;
  const tableLabel = cell.textContent.trim().replace(/\d+p$/, "").trim();
  document.getElementById("selectedTableInfo").textContent = `Selected: ${tableLabel} | Guests: ${document.getElementById("bookingGuests").value}`;
  document.getElementById("confirmBookingBtn").style.display = "block";
}

async function confirmBooking() {
  if (!selectedTableId) return;
  const date = document.getElementById("bookingDate").value;
  const time = document.getElementById("bookingTime").value;
  const guests = parseInt(document.getElementById("bookingGuests").value);

  try {
    const res = await fetch(API + "/api/bookings/create", {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: "Bearer " + token },
      body: JSON.stringify({ date, time, guests, tableId: selectedTableId }),
    });
    const data = await res.json();
    if (!res.ok) return showMsg("bookingMsg", data.error, "error");

    showMsg("bookingMsg", "Table booked successfully!", "success");
    selectedTableId = null;
    document.getElementById("selectedTableInfo").textContent = "";
    document.getElementById("confirmBookingBtn").style.display = "none";
    loadMyBookings();
    checkAvailability();
  } catch {
    showMsg("bookingMsg", "Error creating booking", "error");
  }
}

async function loadMyBookings() {
  if (!token || !user || user.role !== "user") return;
  try {
    const res = await fetch(API + "/api/bookings/my", {
      headers: { Authorization: "Bearer " + token },
    });
    if (!res.ok) return;
    const bookings = await res.json();
    const list = document.getElementById("myBookingsList");
    if (!bookings.length) {
      list.innerHTML = "<p style='color:#a0a0b0;'>No bookings yet.</p>";
      return;
    }
    list.innerHTML = "";
    const today = new Date().toISOString().split("T")[0];
    bookings.forEach((b) => {
      const card = document.createElement("div");
      card.className = "booking-card";
      const canCancel = b.status === "confirmed";
      card.innerHTML = `
        <div class="details">
          <span>${b.date}</span>
          <span>${b.time}</span>
          <span>${b.guests} guest${b.guests > 1 ? "s" : ""}</span>
          <span>${b.tableLabel || "Table " + b.tableId}</span>
        </div>
        <div style="display:flex;align-items:center;gap:8px;">
          <span class="status ${b.status}">${b.status}</span>
          ${canCancel ? `<button class="btn btn-danger btn-small" onclick="cancelBooking(${b.id}, ${b.date === today ? 'true' : 'false'})">Cancel</button>` : ""}
        </div>
      `;
      list.appendChild(card);
    });
  } catch {
    // silent
  }
}

async function cancelBooking(bookingId, isSameDay) {
  const msg = isSameDay
    ? "Cancel this booking? A 80% cancellation charge applies (only 20% refund). Continue?"
    : "Are you sure you want to cancel this booking?";
  if (!confirm(msg)) return;
  try {
    const res = await fetch(API + "/api/bookings/cancel", {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: "Bearer " + token },
      body: JSON.stringify({ bookingId }),
    });
    const data = await res.json();
    if (!res.ok) return showMsg("bookingMsg", data.error, "error");
    showMsg("bookingMsg", data.message, "success");
    loadMyBookings();
  } catch {
    showMsg("bookingMsg", "Error cancelling booking", "error");
  }
}

// ─── OFFERS CAROUSEL ───
let currentSlide = 0;
let slideInterval;
const track = document.getElementById("carouselTrack");
const dotsContainer = document.getElementById("carouselDots");

async function loadOffers() {
  if (!track) return;
  try {
    const res = await fetch("/api/offers");
    const data = await res.json();
    const slides = track.querySelectorAll(".carousel-slide");
    data.offers.forEach((offer) => {
      const slide = track.querySelector(`[data-slot="${offer.slot}"]`);
      if (!slide) return;
      const img = slide.querySelector(".offer-img");
      const placeholder = slide.querySelector(".offer-placeholder");
      const label = slide.querySelector(".offer-label");
      if (offer.image) {
        img.src = offer.image;
        img.style.display = "block";
        placeholder.style.display = "none";
      } else {
        img.style.display = "none";
        placeholder.style.display = "flex";
      }
      if (label) label.textContent = offer.label;
    });
  } catch {}
}

function initCarousel() {
  if (!track) return;
  const slides = track.querySelectorAll(".carousel-slide");
  slides.forEach((_, i) => {
    const dot = document.createElement("span");
    dot.onclick = () => goToSlide(i);
    dotsContainer.appendChild(dot);
  });
  loadOffers();
  goToSlide(0);
  startAutoSlide();
}

function goToSlide(index) {
  if (!track) return;
  const slides = track.querySelectorAll(".carousel-slide");
  if (index < 0) index = slides.length - 1;
  if (index >= slides.length) index = 0;
  currentSlide = index;
  track.style.transform = "translateX(-" + (currentSlide * 100) + "%)";
  const dots = dotsContainer.querySelectorAll("span");
  dots.forEach((d, i) => d.classList.toggle("active", i === currentSlide));
}

function slideOffers(dir) {
  goToSlide(currentSlide + dir);
  resetAutoSlide();
}

function startAutoSlide() {
  stopAutoSlide();
  slideInterval = setInterval(() => goToSlide(currentSlide + 1), 4000);
}

function stopAutoSlide() {
  if (slideInterval) clearInterval(slideInterval);
}

function resetAutoSlide() {
  startAutoSlide();
}

document.addEventListener("DOMContentLoaded", initCarousel);

document.addEventListener("visibilitychange", async () => {
  if (document.visible && token && user) {
    try {
      const res = await fetch("/api/auth/me");
      const data = await res.json();
      if (!data.user) logout();
    } catch { logout(); }
  }
});

// ─── INIT ───


