{{/*
    Return the proper image name
*/}}
{{- define "app.image" -}}
{{ include "common.images.image" (dict "imageRoot" .Values.image "global" .Values.global) }}
{{- end -}}


{{/*
 Create the name of the service account to use
 */}}
{{- define "app.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
    {{ default (include "common.names.fullname" .) .Values.serviceAccount.name }}
{{- else -}}
    {{ default "default" .Values.serviceAccount.name }}
{{- end -}}
{{- end -}}

{{/*
Return the secret name.
*/}}
{{- define "app.secretName" -}}
{{- if .Values.existingSecrets }}
    {{- printf "%s" (tpl .Values.existingSecrets $) -}}
{{- else -}}
    {{- printf "%s" (include "common.names.fullname" .) -}}
{{- end -}}
{{- end -}}
