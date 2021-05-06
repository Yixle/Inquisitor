import os
import nmap
import datetime
import email, smtplib, ssl
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from docx import Document



def emailSender(reciever):
        emailport = 587
        password = "toby6poo6bite6*"
        sender = "smartpentestreport@gmail.com"
        subject = "Smart Report and Text dump from Inquisitor"
        #Mime stuff
        message = MIMEMultipart()
        message["From"] = sender
        message["To"] = reciever
        message["Subject"] = subject
        html = """\
        <html>
         <body>
          <div style="text-align:center;">
           <img src="https://drive.google.com/uc?export=view&id=1jpl4bItstEtP-vcoL-yDQ1dy969bY2je" title="Inquisitor" width="600" height="400" />
           <h3>Greetings</h3><br>
           <p>Please find attached the full report of my findings from the Penetration Test  and a text file containing the raw data from scans.<br>
           Thank you for using Inquisitor.
           </p>
          </div> 
         </body>
        </html>
        """
        htmlpart = MIMEText(html, "html")
        message.attach(htmlpart)

        filename = ['report.docx', 'textdump.txt']
        for filename in filename or []:
                with open(filename, "rb") as attachment:
                        part =MIMEBase("application", "octet-stream")
                        part.set_payload(attachment.read())
                        encoders.encode_base64(part)
                        part.add_header(
                                "Content-Disposition",
                                'attachment; filename= "%s"' % os.path.basename(filename))
                        message.attach(part)	
		
        #Adding the Attachement 
        text = message.as_string()

        #Sending the email
        context = ssl.create_default_context()
        with smtplib.SMTP('smtp.gmail.com', emailport) as server:
            server.ehlo()
            server.starttls()
            server.login(sender, password)

            server.sendmail(sender, reciever, text)
