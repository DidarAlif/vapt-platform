"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import Image from "next/image";

const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000";

export default function RegisterPage() {
    const router = useRouter();
    const [name, setName] = useState("");
    const [email, setEmail] = useState("");
    const [password, setPassword] = useState("");
    const [confirmPassword, setConfirmPassword] = useState("");
    const [error, setError] = useState("");
    const [loading, setLoading] = useState(false);

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        setLoading(true);
        setError("");

        if (password !== confirmPassword) {
            setError("Passwords do not match");
            setLoading(false);
            return;
        }

        if (password.length < 6) {
            setError("Password must be at least 6 characters");
            setLoading(false);
            return;
        }

        try {
            console.log("Registering to:", `${API_URL}/auth/register`);

            const response = await fetch(`${API_URL}/auth/register`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ name, email, password }),
            });

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.detail || "Registration failed");
            }

            // Store tokens
            localStorage.setItem("access_token", data.access_token);
            localStorage.setItem("refresh_token", data.refresh_token);
            localStorage.setItem("user", JSON.stringify(data.user));

            router.push("/scan");
        } catch (err) {
            console.error("Registration error:", err);
            if (err instanceof TypeError && err.message === "Failed to fetch") {
                setError(`Cannot connect to server. API: ${API_URL}`);
            } else {
                setError(err instanceof Error ? err.message : "Registration failed");
            }
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="min-h-screen bg-[#0a0a0f] flex items-center justify-center px-4 py-8">
            <div className="w-full max-w-md">
                {/* Logo */}
                <div className="text-center mb-8">
                    <div className="w-20 h-20 mx-auto relative mb-4">
                        <Image src="/logo.png" alt="ReconScience" fill className="object-contain" />
                    </div>
                    <h1 className="text-2xl font-bold text-gray-100">Create Account</h1>
                    <p className="text-gray-500 text-sm mt-1">Join ReconScience security platform</p>
                </div>

                {/* Register Form */}
                <form onSubmit={handleSubmit} className="bg-[#12121a] border border-gray-800/50 rounded-xl p-6 shadow-2xl">
                    {error && (
                        <div className="mb-4 p-3 bg-red-500/10 border border-red-500/30 rounded-lg text-red-400 text-sm">
                            {error}
                        </div>
                    )}

                    <div className="mb-4">
                        <label className="block text-xs text-gray-400 uppercase mb-2 font-mono">Full Name</label>
                        <input
                            type="text"
                            value={name}
                            onChange={(e) => setName(e.target.value)}
                            required
                            className="w-full bg-[#0a0a0f] border border-gray-700/50 rounded-lg px-4 py-3 text-gray-100 placeholder-gray-600 focus:border-cyan-500/50 focus:ring-2 focus:ring-cyan-500/20 transition-all"
                            placeholder="John Doe"
                        />
                    </div>

                    <div className="mb-4">
                        <label className="block text-xs text-gray-400 uppercase mb-2 font-mono">Email</label>
                        <input
                            type="email"
                            value={email}
                            onChange={(e) => setEmail(e.target.value)}
                            required
                            className="w-full bg-[#0a0a0f] border border-gray-700/50 rounded-lg px-4 py-3 text-gray-100 placeholder-gray-600 focus:border-cyan-500/50 focus:ring-2 focus:ring-cyan-500/20 transition-all"
                            placeholder="your@email.com"
                        />
                    </div>

                    <div className="mb-4">
                        <label className="block text-xs text-gray-400 uppercase mb-2 font-mono">Password</label>
                        <input
                            type="password"
                            value={password}
                            onChange={(e) => setPassword(e.target.value)}
                            required
                            className="w-full bg-[#0a0a0f] border border-gray-700/50 rounded-lg px-4 py-3 text-gray-100 placeholder-gray-600 focus:border-cyan-500/50 focus:ring-2 focus:ring-cyan-500/20 transition-all"
                            placeholder="••••••••"
                        />
                    </div>

                    <div className="mb-6">
                        <label className="block text-xs text-gray-400 uppercase mb-2 font-mono">Confirm Password</label>
                        <input
                            type="password"
                            value={confirmPassword}
                            onChange={(e) => setConfirmPassword(e.target.value)}
                            required
                            className="w-full bg-[#0a0a0f] border border-gray-700/50 rounded-lg px-4 py-3 text-gray-100 placeholder-gray-600 focus:border-cyan-500/50 focus:ring-2 focus:ring-cyan-500/20 transition-all"
                            placeholder="••••••••"
                        />
                    </div>

                    <button
                        type="submit"
                        disabled={loading}
                        className="w-full py-3 bg-gradient-to-r from-emerald-600 to-cyan-600 hover:from-emerald-500 hover:to-cyan-500 text-white font-semibold rounded-lg transition-all disabled:opacity-50 shadow-lg shadow-emerald-900/30"
                    >
                        {loading ? "Creating account..." : "Create Account"}
                    </button>

                    <p className="mt-4 text-center text-gray-500 text-sm">
                        Already have an account?{" "}
                        <Link href="/login" className="text-cyan-400 hover:text-cyan-300">
                            Sign in
                        </Link>
                    </p>
                </form>

                <p className="mt-6 text-center text-gray-600 text-xs">
                    © 2026 Alif. All rights reserved.
                </p>
            </div>
        </div>
    );
}
