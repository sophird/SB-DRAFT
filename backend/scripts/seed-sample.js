require("dotenv").config();

const { createClient } = require("@supabase/supabase-js");

// Seed sample profile records for local development/testing.
async function main() {
  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY;

  if (!url || !key) {
    throw new Error("SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are required for seeding.");
  }

  const supabase = createClient(url, key);

  const residents = [
    {
      email: "sophia.resident@example.com",
      full_name: "Sophia Dela Cruz",
      role: "resident"
    },
    {
      email: "admin.burgos@example.com",
      full_name: "Admin Burgos",
      role: "admin"
    }
  ];

  const { error } = await supabase.from("profiles").upsert(residents, { onConflict: "email" });

  if (error) {
    throw new Error(`Seed failed: ${error.message}`);
  }

  console.log("Seed complete: sample profiles inserted/updated.");
}

// Report seed failure and exit with a non-zero status code.
main().catch((err) => {
  console.error(err.message || err);
  process.exit(1);
});
