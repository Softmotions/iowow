//--------------------------  DEBUG STAFF


void iwkvd_trigger_xor(uint64_t val) {
  g_trigger ^= val;
}

void iwkvd_kvblk(FILE *f, KVBLK *kb, int maxvlen) {
  assert(f && kb && kb->addr);
  uint8_t *mm, *vbuf, *kbuf;
  uint32_t klen, vlen;
  IWFS_FSM *fsm = &kb->db->iwkv->fsm;
  blkn_t blkn = ADDR2BLK(kb->addr);
  fprintf(f, "\n === KVBLK[%u] maxoff=%" PRIx64 ", zidx=%d, idxsz=%d, szpow=%u, flg=%x, db=%d\n",
          blkn, kb->maxoff, kb->zidx, kb->idxsz, kb->szpow, kb->flags, kb->db->id);

  iwrc rc = fsm->probe_mmap(fsm, 0, &mm, 0);
  if (rc) {
    iwlog_ecode_error3(rc);
    return;
  }
  for (int i = 0; i < KVBLK_IDXNUM; ++i) {
    KVP *kvp = &kb->pidx[i];
    rc = _kvblk_peek_key(kb, i, mm, &kbuf, &klen);
    if (rc) {
      iwlog_ecode_error3(rc);
      return;
    }
    _kvblk_value_peek(kb, i, mm, &vbuf, &vlen);
    fprintf(f, "\n    %02d: [%04" PRIx64 ", %02u, %02d]: %.*s:%.*s",
            i, kvp->off, kvp->len, kvp->ridx,
            klen, kbuf, MIN(vlen, maxvlen), vbuf);
  }
  fprintf(f, "\n");
}

#define IWKVD_MAX_VALSZ 96

iwrc iwkvd_sblk(FILE *f, IWLCTX *lx, SBLK *sb, int flags) {
  assert(sb && sb->addr);
  uint32_t lkl = 0;
  char lkbuf[SBLK_LKLEN + 1] = {0};
  uint8_t *mm, *vbuf, *kbuf;
  uint32_t klen, vlen;
  IWFS_FSM *fsm = &sb->db->iwkv->fsm;
  blkn_t blkn = ADDR2BLK(sb->addr);
  iwrc rc = fsm->probe_mmap(fsm, 0, &mm, 0);
  if (rc) {
    iwlog_ecode_error3(rc);
    return rc;
  }
  rc = _sblk_loadkvblk_mm(lx, sb, mm);
  if (rc) {
    iwlog_ecode_error3(rc);
    return rc;
  }
  assert(sb->kvblk);
  if (sb->flags & SBLK_DB) {
    lkl = 0;
  } else {
    memcpy(&lkl, mm + sb->addr + SOFF_LKL_U1, 1);
    lkl = IW_ITOHL(lkl);
    memcpy(lkbuf, mm + sb->addr + SOFF_LK, lkl);
  }
  fprintf(f, "\n === SBLK[%u] lvl=%d, pnum=%d, flg=%x, kvzidx=%d, p0=%u, db=%u",
          blkn,
          ((IWKVD_PRINT_NO_LEVEVELS & flags) ? -1 : sb->lvl),
          sb->pnum, sb->flags, sb->kvblk->zidx,
          sb->p0,
          sb->kvblk->db->id);

  fprintf(f, "\n === SBLK[%u] szpow=%d, lkl=%d, lk=%s\n", blkn, sb->kvblk->szpow, lkl, lkbuf);

  for (int i = 0, j = 0; i < sb->pnum; ++i, ++j) {
    if (j == 3) {
      fputc('\n', f);
      j = 0;
    }
    if (j == 0) {
      fprintf(f, " === SBLK[%u]", blkn);
    }
    rc = _kvblk_peek_key(sb->kvblk, sb->pi[i], mm, &kbuf, &klen);
    if (rc) {
      iwlog_ecode_error3(rc);
      return rc;
    }
    if (flags & IWKVD_PRINT_VALS) {
      _kvblk_value_peek(sb->kvblk, sb->pi[i], mm, &vbuf, &vlen);
      fprintf(f, "    [%03d,%03d] %.*s:%.*s", i, sb->pi[i], klen, kbuf, MIN(vlen, IWKVD_MAX_VALSZ), vbuf);
    } else {
      fprintf(f, "    [%03d,%03d] %.*s", i, sb->pi[i], klen, kbuf);
    }
  }
  fprintf(f, "\n\n");
  return rc;
}

IWFS_FSM *iwkvd_fsm(IWKV kv) {
  return &kv->fsm;
}

void iwkvd_db(FILE *f, IWDB db, int flags, int plvl) {
  assert(db);
  SBLK *sb, *tail;
  IWLCTX lx = {
    .db = db,
    .nlvl = -1
  };
  iwrc rc = _sblk_at(&lx, db->addr, 0, &sb);
  if (rc) {
    iwlog_ecode_error3(rc);
    return;
  }
  rc = _sblk_at(&lx, 0, 0, &tail);
  if (rc) {
    iwlog_ecode_error3(rc);
    return;
  }
  fprintf(f, "\n\n== DB[%u] lvl=%d, blk=%u, dbflg=%x, p0=%u",
          db->id,
          ((IWKVD_PRINT_NO_LEVEVELS & flags) ? -1 : sb->lvl),
          (unsigned int) ADDR2BLK(sb->addr),
          db->dbflg,
          tail->p0);
  if (!(IWKVD_PRINT_NO_LEVEVELS & flags)) {
    fprintf(f, "\n== DB[%u]->n=[", db->id);
    for (int i = 0; i <= sb->lvl; ++i) {
      if (i > 0) {
        fprintf(f, ", %d:%u", i, sb->n[i]);
      } else {
        fprintf(f, "%d:%u", i, sb->n[i]);
      }
    }
    fprintf(f, "]");
  }
  blkn_t blk = sb->n[plvl];
  while (blk) {
    rc = _sblk_at(&lx, BLK2ADDR(blk), 0, &sb);
    if (rc) {
      iwlog_ecode_error3(rc);
      return;
    }
    iwkvd_sblk(f, &lx, sb, flags);
    blk = sb->n[plvl];
    _sblk_release(&lx, &sb);
  }
  fflush(f);
}


