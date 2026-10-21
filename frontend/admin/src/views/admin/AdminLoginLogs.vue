<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { useDebounceFn } from '@vueuse/core'
import { useI18n } from 'vue-i18n'
import { adminAPI } from '@/api/admin'
import type { AdminLoginBan, AdminLoginGuardConfig, AdminLoginLog } from '@/api/types'
import IdCell from '@/components/IdCell.vue'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { Textarea } from '@/components/ui/textarea'
import TableSkeleton from '@/components/TableSkeleton.vue'
import ListPagination from '@/components/ListPagination.vue'
import { useListRefresh, type ListFetchOptions } from '@/composables/useListRefresh'
import { useAdminAuthStore } from '@/stores/auth'
import { formatDate, toRFC3339 } from '@/utils/format'
import { notifyError, notifySuccess } from '@/utils/notify'

const { t } = useI18n()
const authStore = useAdminAuthStore()
const loading = ref(true)
const settingsLoading = ref(false)
const savingSettings = ref(false)
const acting = ref(false)
const configLoaded = ref(false)
const showSettings = ref(false)
const { refreshing, refreshList } = useListRefresh()
const logs = ref<AdminLoginLog[]>([])
const permanentBans = ref<AdminLoginBan[]>([])
const whitelistText = ref('')
const pagination = ref({
  page: 1,
  page_size: 20,
  total: 0,
  total_page: 1,
})
const filters = reactive({
  username: '',
  clientIp: '',
  fingerprint: '',
  status: '__all__',
  failReason: '__all__',
  eventType: '__all__',
  createdFrom: '',
  createdTo: '',
})

const canSaveSettings = computed(() => authStore.hasPermission('PUT:/admin/settings'))
const canUnban = computed(() => authStore.hasPermission('POST:/admin/admin-login-bans/unban'))
const canBan = computed(() => authStore.hasPermission('POST:/admin/admin-login-bans'))

const normalizeFilterValue = (value: string) => (value === '__all__' ? '' : value)

const failReasonOptions = [
  'password_wrong',
  'auto_banned',
  'already_banned',
  'invalid_credentials',
  'invalid_totp_code',
  'invalid_recovery_code',
  'too_many_attempts',
  'challenge_expired',
  'challenge_revoked',
  'captcha_required',
  'captcha_invalid',
  'rate_limited',
  'internal_error',
]

const eventOptions = [
  'login_password',
  'login_2fa_verify',
  'login_recovery_code',
]

const fetchLogs = async (page = 1, options: ListFetchOptions = {}) => {
  if (!options.preserveRows) loading.value = true
  try {
    const response = await adminAPI.getAdminLoginLogs({
      page,
      page_size: pagination.value.page_size,
      username: filters.username || undefined,
      client_ip: filters.clientIp || undefined,
      fingerprint: filters.fingerprint || undefined,
      status: normalizeFilterValue(filters.status) || undefined,
      fail_reason: normalizeFilterValue(filters.failReason) || undefined,
      event_type: normalizeFilterValue(filters.eventType) || undefined,
      created_from: toRFC3339(filters.createdFrom),
      created_to: toRFC3339(filters.createdTo),
    })
    logs.value = response.data.data || []
    pagination.value = response.data.pagination || pagination.value
  } catch {
    if (!options.preserveRows) logs.value = []
  } finally {
    if (!options.preserveRows) loading.value = false
  }
}

const handleSearch = () => {
  fetchLogs(1)
}
const debouncedSearch = useDebounceFn(handleSearch, 300)

const refresh = () => {
  refreshList(async () => {
    await fetchLogs(pagination.value.page, { preserveRows: true })
    if (showSettings.value) await loadConfig()
  })
}

const changePage = (page: number) => {
  if (page < 1 || page > pagination.value.total_page) return
  fetchLogs(page)
}

const pageSizeOptions = [10, 20, 50, 100]

const changePageSize = (size: number) => {
  if (size === pagination.value.page_size) return
  pagination.value.page_size = size
  fetchLogs(1)
}

const statusLabel = (status: string) => t(`admin.adminLoginLogs.status.${status || 'failed'}`)

const statusClass = (status: string) => {
  if (status === 'success') return 'border-emerald-500/30 bg-emerald-500/10 text-emerald-600 dark:text-emerald-300'
  return 'border-rose-500/30 bg-rose-500/10 text-rose-600 dark:text-rose-300'
}

const translated = (prefix: string, value?: string) => {
  const normalized = (value || '').trim()
  if (!normalized) return '-'
  const key = `${prefix}.${normalized}`
  const label = t(key)
  return label === key ? normalized : label
}

const failReasonLabel = (reason?: string) => translated('admin.adminLoginLogs.failReason', reason)
const eventLabel = (event?: string) => translated('admin.adminLoginLogs.event', event)

const shortFingerprint = (value?: string) => {
  const text = (value || '').trim()
  if (!text) return '-'
  if (text.length <= 16) return text
  return `${text.slice(0, 8)}…${text.slice(-6)}`
}

const hasFingerprint = (value?: string) => /^[0-9a-f]{1,128}$/i.test((value || '').trim())

const normalizeLines = (value: string) => Array.from(new Set(value
  .split('\n')
  .map((line) => line.trim())
  .filter((line) => line.length > 0)))

const loadConfig = async () => {
  settingsLoading.value = true
  try {
    const response = await adminAPI.getSettings({ key: 'admin_login_guard_config' })
    const data = (response.data?.data || {}) as AdminLoginGuardConfig
    whitelistText.value = (data.ip_whitelist || []).join('\n')
    permanentBans.value = data.permanent_bans || []
    configLoaded.value = true
  } catch (err) {
    const known = err as Error
    if (known.message === t('common.api.forbidden')) {
      showSettings.value = false
    }
    configLoaded.value = false
  } finally {
    settingsLoading.value = false
  }
}

const saveWhitelist = async () => {
  if (!configLoaded.value || !canSaveSettings.value) return
  savingSettings.value = true
  try {
    await adminAPI.updateSettings({
      key: 'admin_login_guard_config',
      value: {
        ip_whitelist: normalizeLines(whitelistText.value),
        permanent_bans: permanentBans.value,
      },
    })
    notifySuccess(t('admin.common.operationSuccess'))
    await loadConfig()
  } catch (err) {
    const known = err as Error & { __notified?: boolean }
    if (!known?.__notified) notifyError(known?.message || t('admin.common.error'))
  } finally {
    savingSettings.value = false
  }
}

const changeBan = async (
  mode: 'ban' | 'unban',
  clientIP: string,
  fingerprint: string,
  confirmKey: string,
) => {
  const ip = clientIP.trim()
  const fp = fingerprint.trim()
  if (!ip && !fp) return
  if (!window.confirm(t(confirmKey))) return
  acting.value = true
  try {
    const payload = {
      client_ip: ip || undefined,
      fingerprint: fp || undefined,
    }
    if (mode === 'ban') await adminAPI.banAdminLogin(payload)
    else await adminAPI.unbanAdminLogin(payload)
    notifySuccess(t('admin.common.operationSuccess'))
    await fetchLogs(pagination.value.page, { preserveRows: true })
    if (showSettings.value) await loadConfig()
  } catch (err) {
    const known = err as Error & { __notified?: boolean }
    if (!known?.__notified) notifyError(known?.message || t('admin.common.error'))
  } finally {
    acting.value = false
  }
}

onMounted(() => {
  fetchLogs()
  if (authStore.hasPermission('GET:/admin/settings')) {
    showSettings.value = true
    loadConfig()
  }
})
</script>

<template>
  <div class="space-y-6">
    <div class="flex flex-col gap-2">
      <h1 class="text-2xl font-semibold">{{ t('admin.adminLoginLogs.title') }}</h1>
      <p class="text-sm text-muted-foreground">{{ t('admin.adminLoginLogs.hint') }}</p>
    </div>

    <div v-if="showSettings" class="grid gap-4 lg:grid-cols-2">
      <div class="rounded-xl border border-border bg-card p-4 shadow-sm space-y-3">
        <div>
          <Label>{{ t('admin.adminLoginLogs.whitelistTitle') }}</Label>
          <p class="mt-1 text-xs text-muted-foreground">{{ t('admin.adminLoginLogs.whitelistHint') }}</p>
        </div>
        <Textarea
          v-model="whitelistText"
          rows="6"
          :disabled="settingsLoading || !canSaveSettings"
          :placeholder="t('admin.adminLoginLogs.whitelistPlaceholder')"
        />
        <Button size="sm" :disabled="settingsLoading || savingSettings || !configLoaded || !canSaveSettings" @click="saveWhitelist">
          {{ t('admin.common.save') }}
        </Button>
      </div>

      <div class="rounded-xl border border-border bg-card p-4 shadow-sm space-y-3">
        <div>
          <h2 class="text-sm font-medium">{{ t('admin.adminLoginLogs.permanentTitle') }}</h2>
          <p class="mt-1 text-xs text-muted-foreground">{{ t('admin.adminLoginLogs.permanentHint') }}</p>
        </div>
        <p v-if="permanentBans.length === 0" class="text-sm text-muted-foreground">{{ t('admin.adminLoginLogs.permanentEmpty') }}</p>
        <ul v-else class="space-y-2">
          <li v-for="ban in permanentBans" :key="`${ban.kind}:${ban.value}`" class="flex items-center justify-between gap-3 rounded-lg border border-border px-3 py-2">
            <div class="min-w-0">
              <div class="text-xs text-muted-foreground">{{ t(`admin.adminLoginLogs.permanentKind.${ban.kind}`) }}</div>
              <div class="truncate font-mono text-xs" :title="ban.value">{{ ban.value }}</div>
            </div>
            <Button
              v-if="canUnban"
              size="sm"
              variant="outline"
              :disabled="acting"
              @click="changeBan('unban', ban.kind === 'ip' ? ban.value : '', ban.kind === 'fingerprint' ? ban.value : '', ban.kind === 'ip' ? 'admin.adminLoginLogs.confirmUnbanIp' : 'admin.adminLoginLogs.confirmUnbanFingerprint')"
            >
              {{ t('admin.adminLoginLogs.actions.unban') }}
            </Button>
          </li>
        </ul>
      </div>
    </div>

    <div class="rounded-xl border border-border bg-card p-4 shadow-sm">
      <div class="flex flex-col gap-3 sm:flex-row sm:flex-wrap sm:items-center">
        <div class="w-full md:w-40">
          <Input v-model="filters.username" :placeholder="t('admin.adminLoginLogs.filterUsername')" @update:modelValue="debouncedSearch" />
        </div>
        <div class="w-full md:w-40">
          <Input v-model="filters.clientIp" :placeholder="t('admin.adminLoginLogs.filterClientIp')" @update:modelValue="debouncedSearch" />
        </div>
        <div class="w-full md:w-48">
          <Input v-model="filters.fingerprint" :placeholder="t('admin.adminLoginLogs.filterFingerprint')" @update:modelValue="debouncedSearch" />
        </div>
        <div class="w-full md:w-40">
          <Select v-model="filters.status" @update:modelValue="handleSearch">
            <SelectTrigger class="h-9 w-full">
              <SelectValue :placeholder="t('admin.adminLoginLogs.filterStatusAll')" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="__all__">{{ t('admin.adminLoginLogs.filterStatusAll') }}</SelectItem>
              <SelectItem value="success">{{ t('admin.adminLoginLogs.status.success') }}</SelectItem>
              <SelectItem value="failed">{{ t('admin.adminLoginLogs.status.failed') }}</SelectItem>
            </SelectContent>
          </Select>
        </div>
        <div class="w-full md:w-48">
          <Select v-model="filters.failReason" @update:modelValue="handleSearch">
            <SelectTrigger class="h-9 w-full">
              <SelectValue :placeholder="t('admin.adminLoginLogs.filterFailReasonAll')" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="__all__">{{ t('admin.adminLoginLogs.filterFailReasonAll') }}</SelectItem>
              <SelectItem v-for="item in failReasonOptions" :key="item" :value="item">{{ failReasonLabel(item) }}</SelectItem>
            </SelectContent>
          </Select>
        </div>
        <div class="w-full md:w-44">
          <Select v-model="filters.eventType" @update:modelValue="handleSearch">
            <SelectTrigger class="h-9 w-full">
              <SelectValue :placeholder="t('admin.adminLoginLogs.filterEventAll')" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="__all__">{{ t('admin.adminLoginLogs.filterEventAll') }}</SelectItem>
              <SelectItem v-for="item in eventOptions" :key="item" :value="item">{{ eventLabel(item) }}</SelectItem>
            </SelectContent>
          </Select>
        </div>
        <div class="flex w-full flex-col gap-2 md:w-auto md:flex-row md:flex-wrap md:items-center">
          <span class="whitespace-nowrap text-xs text-muted-foreground">{{ t('admin.adminLoginLogs.filterCreatedFrom') }}</span>
          <Input v-model="filters.createdFrom" type="datetime-local" class="h-9 w-full md:w-auto" @update:modelValue="handleSearch" />
          <span class="hidden text-muted-foreground md:inline">-</span>
          <Input v-model="filters.createdTo" type="datetime-local" class="h-9 w-full md:w-auto" @update:modelValue="handleSearch" />
        </div>
        <div class="hidden flex-1 sm:block"></div>
        <Button size="sm" variant="outline" class="w-full sm:w-auto" :disabled="refreshing" @click="refresh">{{ t('admin.common.refresh') }}</Button>
      </div>
    </div>

    <div class="overflow-x-auto rounded-xl border border-border bg-card">
      <Table class="min-w-[1100px]">
        <TableHeader class="border-b border-border bg-muted/40 text-xs uppercase text-muted-foreground">
          <TableRow>
            <TableHead class="px-4 py-3">{{ t('admin.adminLoginLogs.table.id') }}</TableHead>
            <TableHead class="px-4 py-3">{{ t('admin.adminLoginLogs.table.createdAt') }}</TableHead>
            <TableHead class="px-4 py-3">{{ t('admin.adminLoginLogs.table.username') }}</TableHead>
            <TableHead class="px-4 py-3">{{ t('admin.adminLoginLogs.table.event') }}</TableHead>
            <TableHead class="px-4 py-3">{{ t('admin.adminLoginLogs.table.status') }}</TableHead>
            <TableHead class="px-4 py-3">{{ t('admin.adminLoginLogs.table.failReason') }}</TableHead>
            <TableHead class="px-4 py-3">{{ t('admin.adminLoginLogs.table.clientIp') }}</TableHead>
            <TableHead class="px-4 py-3">{{ t('admin.adminLoginLogs.table.fingerprint') }}</TableHead>
            <TableHead class="px-4 py-3">{{ t('admin.adminLoginLogs.table.ipFails') }}</TableHead>
            <TableHead class="px-4 py-3">{{ t('admin.adminLoginLogs.table.fpFails') }}</TableHead>
            <TableHead class="px-4 py-3">{{ t('admin.adminLoginLogs.table.actions') }}</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody class="divide-y divide-border">
          <TableRow v-if="loading">
            <TableCell :colspan="11" class="p-0">
              <TableSkeleton :columns="11" :rows="5" />
            </TableCell>
          </TableRow>
          <TableRow v-else-if="logs.length === 0">
            <TableCell colspan="11" class="px-6 py-8 text-center text-muted-foreground">{{ t('admin.adminLoginLogs.empty') }}</TableCell>
          </TableRow>
          <TableRow v-for="item in logs" :key="item.id" class="hover:bg-muted/30">
            <TableCell class="px-4 py-3"><IdCell :value="item.id" /></TableCell>
            <TableCell class="px-4 py-3 text-xs text-muted-foreground">{{ formatDate(item.created_at) }}</TableCell>
            <TableCell class="px-4 py-3 text-xs">{{ item.username || '-' }}</TableCell>
            <TableCell class="px-4 py-3 text-xs text-muted-foreground">{{ eventLabel(item.event_type) }}</TableCell>
            <TableCell class="px-4 py-3">
              <span class="inline-flex rounded-full border px-2.5 py-1 text-xs" :class="statusClass(item.status)">
                {{ statusLabel(item.status) }}
              </span>
            </TableCell>
            <TableCell class="px-4 py-3 text-xs text-muted-foreground">{{ failReasonLabel(item.fail_reason) }}</TableCell>
            <TableCell class="px-4 py-3 font-mono text-xs break-all">{{ item.client_ip || '-' }}</TableCell>
            <TableCell class="px-4 py-3 font-mono text-xs" :title="item.fingerprint || ''">{{ shortFingerprint(item.fingerprint) }}</TableCell>
            <TableCell class="px-4 py-3 text-xs">{{ item.ip_fail_count || 0 }}</TableCell>
            <TableCell class="px-4 py-3 text-xs">{{ item.fp_fail_count || 0 }}</TableCell>
            <TableCell class="px-4 py-3">
              <div class="flex flex-col gap-1">
                <Button
                  v-if="canUnban && item.client_ip"
                  size="sm"
                  variant="outline"
                  :disabled="acting"
                  @click="changeBan('unban', item.client_ip, '', 'admin.adminLoginLogs.confirmUnbanIp')"
                >
                  {{ t('admin.adminLoginLogs.actions.unbanIp') }}
                </Button>
                <Button
                  v-if="canUnban && hasFingerprint(item.fingerprint)"
                  size="sm"
                  variant="outline"
                  :disabled="acting"
                  @click="changeBan('unban', '', item.fingerprint || '', 'admin.adminLoginLogs.confirmUnbanFingerprint')"
                >
                  {{ t('admin.adminLoginLogs.actions.unbanFingerprint') }}
                </Button>
                <Button
                  v-if="canBan && item.client_ip"
                  size="sm"
                  variant="outline"
                  :disabled="acting"
                  @click="changeBan('ban', item.client_ip, '', 'admin.adminLoginLogs.confirmBanIp')"
                >
                  {{ t('admin.adminLoginLogs.actions.banIp') }}
                </Button>
                <Button
                  v-if="canBan && hasFingerprint(item.fingerprint)"
                  size="sm"
                  variant="outline"
                  :disabled="acting"
                  @click="changeBan('ban', '', item.fingerprint || '', 'admin.adminLoginLogs.confirmBanFingerprint')"
                >
                  {{ t('admin.adminLoginLogs.actions.banFingerprint') }}
                </Button>
              </div>
            </TableCell>
          </TableRow>
        </TableBody>
      </Table>
      <ListPagination
        :page="pagination.page"
        :total-page="pagination.total_page"
        :total="pagination.total"
        :page-size="pagination.page_size"
        :page-size-options="pageSizeOptions"
        @change-page="changePage"
        @change-page-size="changePageSize"
      />
    </div>
  </div>
</template>
