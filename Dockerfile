FROM nginx:alpine

COPY index.html style.css script.js app.json /usr/share/nginx/html/

EXPOSE 80
