import { useEffect, useRef, useState } from 'react'
import Link from 'next/link'
import { useRouter } from 'next/router'
import { IconMenu2 } from '@tabler/icons-react'
import { Button } from '@partly/pitstop/button'
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
} from '@partly/pitstop/sheet'

import { Logomark } from '@/components/Logo'
import { Navigation } from '@/components/Navigation'
import { DESTINATIONS } from '@/lib/navigation.mjs'

export function MobileNavigation({
  navigation,
  destination,
  pathname,
  readerChoices,
  restoredNavigation,
  onExpandedChange,
}) {
  const router = useRouter()
  const [isOpen, setIsOpen] = useState(false)
  const shownPath = useRef(router.asPath)

  useEffect(() => {
    if (shownPath.current === router.asPath) return
    shownPath.current = router.asPath
    setIsOpen(false)
  }, [router.asPath])

  return (
    <Sheet isOpen={isOpen} onOpenChange={setIsOpen}>
      <Button variant="ghost" size="icon" aria-label="Open navigation">
        <IconMenu2 className="size-6" />
      </Button>
      <SheetContent
        side="left"
        className="overflow-y-auto px-4 pb-12 sm:px-6 lg:hidden"
      >
        <SheetHeader className="px-0 pt-1">
          <SheetTitle className="font-display text-sm font-semibold">
            {destination.label}
          </SheetTitle>
          <Link href="/" aria-label="Home page">
            <Logomark className="h-9 w-9" />
          </Link>
        </SheetHeader>
        <div className="mt-5 flex flex-wrap gap-x-4 gap-y-2 border-y py-3 text-sm">
          {DESTINATIONS.filter((item) => item.id !== destination.id).map(
            (item) => (
              <Link
                key={item.id}
                href={item.href}
                className="text-muted-foreground hover:text-foreground font-medium"
              >
                {item.label}
              </Link>
            )
          )}
        </div>
        <div
          data-navigation-scroll
          className="mt-6 max-h-[calc(100vh-12rem)] overflow-y-auto px-1"
        >
          <Navigation
            navigation={navigation}
            destination={destination}
            pathname={pathname}
            readerChoices={readerChoices}
            restoredNavigation={restoredNavigation}
            onExpandedChange={onExpandedChange}
          />
        </div>
      </SheetContent>
    </Sheet>
  )
}
