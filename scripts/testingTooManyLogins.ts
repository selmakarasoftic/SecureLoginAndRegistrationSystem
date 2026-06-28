for (let i = 0; i < 25; i++) {
  fetch("/api/refresh", {
    method: "POST",
    credentials: "include",
    headers: { "Content-Type": "application/json" },
    body: "{}"
  })
    .then(r => r.text())
    .then(text => console.log(i + 1, text));
}


for (let i = 0; i < 12; i++) {
  fetch("/api/login", {
    method: "POST",
    credentials: "include",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      usernameOrEmail: "wronguser",
      password: "WrongPass123!"
    })
  })
    .then(r => r.text())
    .then(text => console.log(i + 1, text));
}