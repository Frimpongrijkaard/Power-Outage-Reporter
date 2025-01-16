document.addEventListener("DOMContentLoaded", () => {
    const reportForm = document.getElementById("reportForm");
    const token = localStorage.getItem("jwt_token"); // Ensure the JWT token is stored in localStorage

    if (!token) {
        alert("You need to log in to submit a report.");
        window.location.href = "/login"; // Redirect to login if token is missing
        return;
    }

    reportForm.addEventListener("submit", async (event) => {
        event.preventDefault();

        // Gather form data
        const description = document.getElementById("description").value.trim();
        const location = document.getElementById("location").value.trim();
        const status = document.getElementById("status").value || "pending";

        // Validate inputs
        if (!description || !location) {
            alert("All fields are required to submit a report.");
            return;
        }

        if (!["pending", "in-progress", "resolved"].includes(status)) {
            alert("Invalid status value.");
            return;
        }

        try {
            const response = await fetch("/make_report", {
                method: "POST",
                headers: {
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Authorization": `Bearer ${token}`, // Attach JWT token
                },
                body: new URLSearchParams({
                    description,
                    location,
                    status,
                }),
            });

            if (response.ok) {
                // Redirect or show success message
                alert("Your report has been successfully submitted!");
                window.location.href = "/dashboard";
            } else if (response.status === 403) {
                alert("Only regular users can submit outage reports.");
                window.location.href = "/dashboard";
            } else {
                const errorData = await response.json();
                alert(`Error: ${errorData.error || "Failed to submit the report"}`);
            }
        } catch (error) {
            console.error("An error occurred while submitting the report:", error);
            alert("An unexpected error occurred. Please try again later.");
        }
    });
});
