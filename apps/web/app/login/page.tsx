"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";

const API_URL = (process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000").replace(/\/$/, "");

export default function LoginPage() {
    const router = useRouter();
    const [email, setEmail] = useState("");
    const [password, setPassword] = useState("");
    const [showPassword, setShowPassword] = useState(false);
    const [error, setError] = useState("");
    const [loading, setLoading] = useState(false);

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        setLoading(true);
        setError("");

        try {
            const response = await fetch(`${API_URL}/auth/login`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ email, password }),
            });

            const data = await response.json();

            if (!response.ok) {
                if (response.status === 403) {
                    router.push(`/verify-email?email=${encodeURIComponent(email)}`);
                    return;
                }
                throw new Error(data.detail || "Login failed");
            }

            localStorage.setItem("access_token", data.access_token);
            localStorage.setItem("refresh_token", data.refresh_token);
            localStorage.setItem("user", JSON.stringify(data.user));
            router.push("/scan");
        } catch (err) {
            console.error("Login error:", err);
            if (err instanceof TypeError && err.message === "Failed to fetch") {
                setError(`Cannot connect to server. API: ${API_URL}`);
            } else {
                setError(err instanceof Error ? err.message : "Login failed");
            }
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="min-h-screen bg-[#12131c] flex items-center justify-center px-4">
            <div className="w-full max-w-md">
                {/* Logo */}
                <div className="text-center mb-8">
                    <div className="w-12 h-12 mx-auto bg-primary-container rounded-xl flex items-center justify-center mb-4">
                        <span
                            className="material-symbols-outlined text-on-primary-container text-2xl"
                            style={{ fontVariationSettings: "'FILL' 1" }}
                        >
                            radar
                        </span>
                    </div>
                    <h1 className="text-2xl font-headline font-bold text-on-surface tracking-tight">Welcome Back</h1>
                    <p className="text-on-surface-variant text-sm mt-1 font-body">Sign in to RECONSCIENCE</p>
                </div>

                {/* Login Form */}
                <form
                    onSubmit={handleSubmit}
                    className="bg-surface-container-low border border-outline-variant/10 rounded-2xl p-8"
                >
                    {error && (
                        <div className="mb-6 p-4 bg-error-container/20 border border-error/30 rounded-xl text-error text-sm flex items-center gap-2">
                            <span className="material-symbols-outlined text-sm">error</span>
                            {error}
                        </div>
                    )}

                    <div className="mb-5">
                        <label className="block text-[10px] font-headline font-bold text-slate-500 uppercase tracking-widest mb-2">
                            Email Address
                        </label>
                        <input
                            type="email"
                            value={email}
                            onChange={(e) => setEmail(e.target.value)}
                            required
                            className="w-full bg-surface-container-lowest border border-outline-variant/20 rounded-xl px-4 py-3.5 text-on-surface placeholder:text-slate-600 focus:border-primary focus:ring-1 focus:ring-primary/20 transition-all outline-none font-body"
                            placeholder="your@email.com"
                        />
                    </div>

                    <div className="mb-8">
                        <label className="block text-[10px] font-headline font-bold text-slate-500 uppercase tracking-widest mb-2">
                            Password
                        </label>
                        <div className="relative">
                            <input
                                type={showPassword ? "text" : "password"}
                                value={password}
                                onChange={(e) => setPassword(e.target.value)}
                                required
                                className="w-full bg-surface-container-lowest border border-outline-variant/20 rounded-xl px-4 py-3.5 pr-12 text-on-surface placeholder:text-slate-600 focus:border-primary focus:ring-1 focus:ring-primary/20 transition-all outline-none font-body"
                                placeholder="••••••••"
                            />
                            <button
                                type="button"
                                onClick={() => setShowPassword(!showPassword)}
                                className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-500 hover:text-on-surface transition-colors"
                            >
                                <span className="material-symbols-outlined text-xl">
                                    {showPassword ? "visibility_off" : "visibility"}
                                </span>
                            </button>
                        </div>
                    </div>

                    <button
                        type="submit"
                        disabled={loading}
                        className="w-full py-3.5 bg-primary-container hover:bg-[#8433c4] text-on-primary-container font-headline font-bold rounded-xl transition-all disabled:opacity-50 active:scale-[0.98] shadow-[0_10px_30px_-10px_rgba(154,74,217,0.3)]"
                    >
                        {loading ? "Signing in..." : "Sign In"}
                    </button>

                    <p className="mt-6 text-center text-on-surface-variant text-sm font-body">
                        Don&apos;t have an account?{" "}
                        <Link href="/register" className="text-primary hover:text-primary-fixed-dim font-medium">
                            Create one
                        </Link>
                    </p>
                </form>

                <p className="mt-8 text-center text-slate-600 text-xs font-headline tracking-widest uppercase">
                    © 2026 Alif. All rights reserved.
                </p>
            </div>
        </div>
    );
}
