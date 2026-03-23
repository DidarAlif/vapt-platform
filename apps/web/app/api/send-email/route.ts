import { NextResponse } from 'next/server';
import nodemailer from 'nodemailer';

export async function POST(request: Request) {
    try {
        const body = await request.json();
        const { to, subject, html, smtp_user, smtp_password } = body;

        if (!to || !subject || !html || !smtp_user || !smtp_password) {
            return NextResponse.json({ error: 'Missing parameters' }, { status: 400 });
        }

        const transporter = nodemailer.createTransport({
            host: 'smtp.gmail.com',
            port: 465,
            secure: true,
            auth: {
                user: smtp_user,
                pass: smtp_password
            }
        });

        await transporter.sendMail({
            from: `"ReconScience" <${smtp_user}>`,
            to,
            subject,
            html
        });

        return NextResponse.json({ success: true });
    } catch (error) {
        console.error('Vercel SMTP Relay Error:', error);
        return NextResponse.json({ error: String(error) }, { status: 500 });
    }
}
