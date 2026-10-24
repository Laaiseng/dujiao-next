<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { adminAPI } from '@/api/admin'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import { notifyError, notifySuccess } from '@/utils/notify'

const { t } = useI18n()

const loading = ref(false)
const submitting = ref(false)

const form = reactive({
  enabled: false,
  base_url: '',
  api_token: '',
})
const hasAPIToken = ref(false)

const loadConfig = async () => {
  loading.value = true
  try {
    const res = await adminAPI.getSettings({ key: 'plus_issue_config' })
    const data = res.data?.data as Record<string, unknown> | undefined
    if (data) {
      hasAPIToken.value = data.has_api_token === true
      form.enabled = data.enabled !== false && Boolean(data.base_url || hasAPIToken.value)
      form.base_url = String(data.base_url || '')
      form.api_token = ''
    }
  } catch {
    // ignore load error, use defaults
  } finally {
    loading.value = false
  }
}

const save = async () => {
  submitting.value = true
  try {
    const baseURL = form.base_url.trim().replace(/\/+$/, '')
    const apiToken = form.api_token.trim()
    if (form.enabled && (!baseURL || (!apiToken && !hasAPIToken.value))) {
      throw new Error(t('admin.settings.plusIssue.requiredError'))
    }
    form.base_url = baseURL
    const res = await adminAPI.updateSettings({
      key: 'plus_issue_config',
      value: { enabled: form.enabled, base_url: baseURL, api_token: apiToken },
    })
    const saved = res.data?.data as Record<string, unknown> | undefined
    hasAPIToken.value = saved?.has_api_token === true
    form.api_token = ''
    notifySuccess(t('admin.settings.alerts.saveSuccess'))
  } catch (err) {
    const known = err as Error & { __notified?: boolean }
    if (!known?.__notified) {
      notifyError(known?.message || t('admin.settings.alerts.saveFailed'))
    }
  } finally {
    submitting.value = false
  }
}

defineExpose({ save, submitting })

onMounted(() => {
  loadConfig()
})
</script>

<template>
  <div class="space-y-6">
    <div class="rounded-lg border p-6">
      <h2 class="text-lg font-semibold">{{ t('admin.settings.plusIssue.title') }}</h2>
      <p class="mt-1 text-xs text-muted-foreground">{{ t('admin.settings.plusIssue.subtitle') }}</p>
    </div>

    <div class="rounded-lg border p-6 space-y-4">
      <div class="flex items-center gap-3">
        <Switch v-model="form.enabled" />
        <Label class="text-sm font-medium">{{ t('admin.settings.plusIssue.enabled') }}</Label>
      </div>
      <p class="text-xs text-muted-foreground">{{ t('admin.settings.plusIssue.enabledHint') }}</p>

      <div class="space-y-1">
        <label class="text-xs font-medium text-muted-foreground">{{ t('admin.settings.plusIssue.baseURL') }}</label>
        <Input v-model="form.base_url" placeholder="http://127.0.0.1:18081" />
        <p class="text-xs text-muted-foreground">{{ t('admin.settings.plusIssue.baseURLHint') }}</p>
      </div>

      <div class="space-y-1">
        <label class="text-xs font-medium text-muted-foreground">{{ t('admin.settings.plusIssue.apiToken') }}</label>
        <Input
          v-model="form.api_token"
          type="password"
          autocomplete="new-password"
          :placeholder="hasAPIToken ? t('admin.settings.plusIssue.apiTokenSet') : ''"
        />
        <p class="text-xs text-muted-foreground">{{ t('admin.settings.plusIssue.apiTokenHint') }}</p>
      </div>
    </div>
  </div>
</template>
